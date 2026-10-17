variable "VERSION" {
  default = "dev"
}

group "default" {
  targets = ["scrutineer-oss-crs-base"]
}

# bake runs from the repository root. The runner image already carries claude,
# the analysis tools and the scrutineer binary, so the auditor module only
# adds libCRS and the entrypoint on top of it.
target "scrutineer-oss-crs-base" {
  context    = "."
  dockerfile = "Dockerfile.runner"
  tags       = ["scrutineer-oss-crs-base:${VERSION}"]
}
