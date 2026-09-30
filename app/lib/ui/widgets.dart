import 'package:flutter/material.dart';

import '../main.dart' show copyToClipboard;

/// Reusable encrypt/decrypt panel used by peer and group screens.
/// [onEncrypt] returns the rendered ciphertext; [onDecrypt] returns a
/// human-readable description of what was decoded.
class CryptoPanel extends StatefulWidget {
  final String Function(String plaintext, String format) onEncrypt;
  final String Function(String input) onDecrypt;
  final String encryptHint;
  const CryptoPanel({
    super.key,
    required this.onEncrypt,
    required this.onDecrypt,
    this.encryptHint = 'Scrivi il messaggio da cifrare…',
  });

  @override
  State<CryptoPanel> createState() => _CryptoPanelState();
}

class _CryptoPanelState extends State<CryptoPanel> {
  final _plainCtrl = TextEditingController();
  final _inCtrl = TextEditingController();
  String _format = 'blob';
  String? _output;
  String? _decoded;
  String? _error;

  @override
  void dispose() {
    _plainCtrl.dispose();
    _inCtrl.dispose();
    super.dispose();
  }

  void _encrypt() {
    setState(() {
      _error = null;
      try {
        _output = widget.onEncrypt(_plainCtrl.text, _format);
      } catch (e) {
        _error = '$e';
        _output = null;
      }
    });
  }

  void _decrypt() {
    setState(() {
      _error = null;
      try {
        _decoded = widget.onDecrypt(_inCtrl.text.trim());
      } catch (e) {
        _decoded = null;
        _error = '$e';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text('Cifra', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        TextField(
          controller: _plainCtrl,
          maxLines: 3,
          decoration: InputDecoration(
              border: const OutlineInputBorder(), hintText: widget.encryptHint),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: SegmentedButton<String>(
                segments: const [
                  ButtonSegment(value: 'blob', label: Text('Blob')),
                  ButtonSegment(value: 'emoji', label: Text('Emoji')),
                  ButtonSegment(value: 'words', label: Text('Parole')),
                ],
                selected: {_format},
                onSelectionChanged: (s) =>
                    setState(() => _format = s.first),
              ),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _encrypt,
              icon: const Icon(Icons.enhanced_encryption),
              label: const Text('Cifra'),
            ),
          ],
        ),
        if (_output != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              border: Border.all(color: Colors.white24),
              borderRadius: BorderRadius.circular(8),
            ),
            child: SelectableText(_output!,
                maxLines: 8,
                style:
                    const TextStyle(fontFamily: 'monospace', fontSize: 12)),
          ),
          const SizedBox(height: 8),
          Row(children: [
            FilledButton.tonalIcon(
              onPressed: () =>
                  copyToClipboard(context, _output!, 'Cifrato copiato'),
              icon: const Icon(Icons.copy),
              label: const Text('Copia e incolla dove vuoi'),
            ),
          ]),
        ],
        const Divider(height: 40),
        Text('Decifra', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        TextField(
          controller: _inCtrl,
          maxLines: 3,
          decoration: const InputDecoration(
            border: OutlineInputBorder(),
            hintText: 'Incolla qui il blob/emoji/parole ricevuto…',
          ),
        ),
        const SizedBox(height: 8),
        FilledButton.tonalIcon(
          onPressed: _decrypt,
          icon: const Icon(Icons.lock_open),
          label: const Text('Decifra'),
        ),
        if (_decoded != null) ...[
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.green.withValues(alpha: 0.08),
              border: Border.all(color: Colors.green.shade700),
              borderRadius: BorderRadius.circular(8),
            ),
            child:
                SelectableText(_decoded!, style: const TextStyle(fontSize: 14)),
          ),
        ],
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Text(_error!,
                style:
                    TextStyle(color: Theme.of(context).colorScheme.error)),
          ),
      ],
    );
  }
}
