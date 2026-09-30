import 'package:flutter/material.dart';

import '../store.dart';
import 'widgets.dart';

class PeerScreen extends StatelessWidget {
  final Contact contact;
  const PeerScreen({super.key, required this.contact});

  @override
  Widget build(BuildContext context) {
    final paired = contact.session != null;
    return Scaffold(
      appBar: AppBar(
        title: Text(contact.name),
        actions: [
          IconButton(
            tooltip: 'Codice di sicurezza',
            icon: const Icon(Icons.fingerprint),
            onPressed: () {
              final sas = store.fingerprintFor(contact);
              showDialog(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Codice di sicurezza'),
                  content: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Text(
                          'Confronta questo codice con quello del peer, di '
                          'persona o su un canale fidato. Se coincide, la '
                          'connessione non è intercettata.'),
                      const SizedBox(height: 16),
                      SelectableText(sas,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 18,
                              letterSpacing: 1.5)),
                    ],
                  ),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: const Text('Chiudi')),
                    FilledButton(
                      onPressed: () {
                        store.markVerified(contact, true);
                        Navigator.pop(ctx);
                      },
                      child: const Text('Segna verificato'),
                    ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
      body: paired
          ? CryptoPanel(
              onEncrypt: (pt, fmt) => store.encryptFor(contact, pt, fmt),
              onDecrypt: (input) {
                final r = store.processInbound(input);
                return switch (r.kind) {
                  'text' => r.text,
                  'card' => 'Ricevuta carta contatto (peer ${r.peerId})',
                  'group_text' => '[gruppo] ${r.text}',
                  _ => r.text,
                };
              },
            )
          : Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  'Contatto non ancora abbinato.\n'
                  'Inviagli la tua carta contatto dalla schermata Contatti.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyLarge,
                ),
              ),
            ),
    );
  }
}
