package skills

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type schemaBundler struct {
	boundary string
	rootDefs map[string]any
	imports  map[string]map[string]any
	docKeys  map[string]string
	usedKeys map[string]bool
}

// bundleLocalSchemaRefs resolves relative file references while a skill is
// loaded. The returned schema is self-contained because DB-backed skills and
// scan workspaces only carry one schema.json file.
func bundleLocalSchemaRefs(schemaPath, boundary, schemaJSON string) (string, error) {
	rootObject, isObject, err := decodeSchemaObject([]byte(schemaJSON))
	if err != nil {
		return "", err
	}
	if !isObject {
		return schemaJSON, nil
	}
	realBoundary, err := filepath.EvalSymlinks(boundary)
	if err != nil {
		return "", fmt.Errorf("resolve schema boundary: %w", err)
	}
	realBoundary, err = filepath.Abs(realBoundary)
	if err != nil {
		return "", fmt.Errorf("make schema boundary absolute: %w", err)
	}

	rootDefs, err := schemaDefs(rootObject)
	if err != nil {
		return "", err
	}
	bundler := &schemaBundler{
		boundary: realBoundary,
		rootDefs: rootDefs,
		imports:  make(map[string]map[string]any),
		docKeys:  make(map[string]string),
		usedKeys: make(map[string]bool, len(rootDefs)),
	}
	for key := range rootDefs {
		bundler.usedKeys[key] = true
	}
	changed, err := bundler.rewrite(rootObject, schemaPath, "")
	if err != nil {
		return "", err
	}
	if !changed {
		return schemaJSON, nil
	}
	for key, imported := range bundler.imports {
		rootDefs[key] = imported
	}
	rootObject["$defs"] = rootDefs
	raw, err := json.MarshalIndent(rootObject, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode bundled schema: %w", err)
	}
	return string(raw) + "\n", nil
}

func decodeSchemaObject(raw []byte) (map[string]any, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var schema any
	if err := decoder.Decode(&schema); err != nil {
		return nil, false, fmt.Errorf("decode schema: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nil, false, fmt.Errorf("decode schema: multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("decode schema: %w", err)
	}
	object, ok := schema.(map[string]any)
	return object, ok, nil
}

func schemaDefs(root map[string]any) (map[string]any, error) {
	value, ok := root["$defs"]
	if !ok {
		return make(map[string]any), nil
	}
	defs, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema $defs must be an object")
	}
	return defs, nil
}

func (b *schemaBundler) rewrite(value any, documentPath, pointerPrefix string) (bool, error) {
	switch current := value.(type) {
	case map[string]any:
		changed := false
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "$ref" {
				ref, ok := current[key].(string)
				if !ok {
					return false, fmt.Errorf("schema $ref must be a string")
				}
				rewritten, refChanged, err := b.rewriteRef(ref, documentPath, pointerPrefix)
				if err != nil {
					return false, err
				}
				current[key] = rewritten
				changed = changed || refChanged
				continue
			}
			childChanged, err := b.rewrite(current[key], documentPath, pointerPrefix)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	case []any:
		changed := false
		for i := range current {
			childChanged, err := b.rewrite(current[i], documentPath, pointerPrefix)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	default:
		return false, nil
	}
}

func (b *schemaBundler) rewriteRef(ref, documentPath, pointerPrefix string) (string, bool, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return "", false, fmt.Errorf("parse schema reference %q: %w", ref, err)
	}
	if parsed.Path == "" {
		if pointerPrefix == "" {
			return ref, false, nil
		}
		if parsed.Fragment != "" && !strings.HasPrefix(parsed.Fragment, "/") {
			return "", false, fmt.Errorf("schema reference %q uses an unsupported anchor", ref)
		}
		return pointerPrefix + parsed.Fragment, true, nil
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return ref, false, nil
	}
	if parsed.RawQuery != "" {
		return "", false, fmt.Errorf("schema reference %q contains a query", ref)
	}
	if filepath.IsAbs(parsed.Path) || strings.Contains(parsed.Path, `\`) {
		return "", false, fmt.Errorf("schema reference %q is not a relative slash-separated path", ref)
	}
	if parsed.Fragment != "" && !strings.HasPrefix(parsed.Fragment, "/") {
		return "", false, fmt.Errorf("schema reference %q uses an unsupported anchor", ref)
	}

	resolved, err := b.resolve(documentPath, parsed.Path)
	if err != nil {
		return "", false, err
	}
	key, err := b.bundleDocument(resolved)
	if err != nil {
		return "", false, err
	}
	return "#/$defs/" + escapeJSONPointer(key) + parsed.Fragment, true, nil
}

func (b *schemaBundler) resolve(documentPath, refPath string) (string, error) {
	target := filepath.Join(filepath.Dir(documentPath), filepath.FromSlash(refPath))
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("resolve schema reference %q: %w", refPath, err)
	}
	realTarget, err = filepath.Abs(realTarget)
	if err != nil {
		return "", fmt.Errorf("make schema reference %q absolute: %w", refPath, err)
	}
	rel, err := filepath.Rel(b.boundary, realTarget)
	if err != nil {
		return "", fmt.Errorf("check schema reference %q containment: %w", refPath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("schema reference %q escapes the skill collection", refPath)
	}
	return realTarget, nil
}

func (b *schemaBundler) bundleDocument(path string) (string, error) {
	if key, ok := b.docKeys[path]; ok {
		return key, nil
	}
	key := b.documentKey(path)
	b.docKeys[path] = key
	b.usedKeys[key] = true
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read referenced schema %s: %w", path, err)
	}
	document, isObject, err := decodeSchemaObject(raw)
	if err != nil {
		return "", fmt.Errorf("referenced schema %s: %w", path, err)
	}
	if !isObject {
		return "", fmt.Errorf("referenced schema %s must be an object", path)
	}
	prefix := "#/$defs/" + escapeJSONPointer(key)
	_, err = b.rewrite(document, path, prefix)
	if err != nil {
		return "", err
	}
	b.imports[key] = document
	return key, nil
}

func (b *schemaBundler) documentKey(path string) string {
	key := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	key = strings.TrimSuffix(key, ".schema")
	if key == "" {
		key = "schema"
	}
	candidate := key
	for i := 2; ; i++ {
		if !b.usedKeys[candidate] {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", key, i)
	}
}

func escapeJSONPointer(value string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(value)
}
