import 'package:flutter/material.dart';
import 'package:secure_notes/secure_notes.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatefulWidget {
  const ExampleApp({super.key});

  @override
  State<ExampleApp> createState() => _ExampleAppState();
}

class _ExampleAppState extends State<ExampleApp> {
  final _controller = TextEditingController();
  String _stored = '';

  Future<void> _roundTrip() async {
    await SecureNotes.save('demo', _controller.text);
    final value = await SecureNotes.read('demo');
    setState(() => _stored = value ?? '');
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
        home: Scaffold(
          appBar: AppBar(title: const Text('secure_notes example')),
          body: Column(children: [
            TextField(controller: _controller),
            ElevatedButton(onPressed: _roundTrip, child: const Text('Save and read')),
            Text('Stored: $_stored'),
          ]),
        ),
      );
}
