import 'package:flutter/material.dart';

import '../store.dart';
import 'chat_panel.dart';

class PeerScreen extends StatelessWidget {
  final Contact contact;
  const PeerScreen({super.key, required this.contact});

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: store,
      builder: (_, __) => _build(context),
    );
  }

  Widget _build(BuildContext context) {
    final paired = contact.session != null;
    return Scaffold(
      appBar: AppBar(
        title: Row(children: [
          Text(contact.name),
          if (contact.verified) ...[
            const SizedBox(width: 6),
            const Icon(Icons.verified_user, size: 18),
          ],
        ]),
        actions: [
          IconButton(
            tooltip: 'Codice di sicurezza',
            icon: const Icon(Icons.fingerprint),
            onPressed: () => _showSas(context),
          ),
        ],
      ),
      body: paired
          ? ChatPanel(
              historyKey: Store.historyKeyForContact(contact.pubId),
              onSend: (pt, fmt) => store.encryptFor(contact, pt, fmt),
              onReceive: (input) => _decode(context, input),
            )
          : const Center(
              child: Padding(
                padding: EdgeInsets.all(32),
                child: Text(
                  'Non sei ancora collegato.\n'
                  'Torna indietro, mostra il tuo codice all\'amico '
                  'e incolla il suo.',
                  textAlign: TextAlign.center,
                ),
              ),
            ),
    );
  }

  ReceivedMsg _decode(BuildContext context, String input) {
    final r = store.processInbound(input);
    switch (r.kind) {
      case 'card':
        _offerAddContact(context, r.text);
        return const ReceivedMsg('Ha mandato il suo codice di contatto.',
            system: true);
      case 'group_text':
        return ReceivedMsg(r.text, from: _peerName(r.peerId));
      case 'info':
        return ReceivedMsg(r.text, system: true);
      default:
        return ReceivedMsg(r.text, from: contact.name);
    }
  }

  String? _peerName(String? pubId) {
    if (pubId == null) return null;
    if (pubId == store.pubId) return 'Tu';
    for (final c in store.contacts) {
      if (c.pubId == pubId) return c.name;
    }
    return pubId.substring(0, 8);
  }

  /// A contact card pasted into the chat can actually be used — offer to save
  /// it as a friend instead of just showing a dead-end message.
  void _offerAddContact(BuildContext context, String cardB64) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!context.mounted) return;
      final nameCtrl = TextEditingController();
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Codice di un contatto'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                  'Questo codice appartiene a qualcuno che vuole collegarsi '
                  'con te. Vuoi aggiungerlo ai tuoi amici?'),
              const SizedBox(height: 12),
              TextField(
                controller: nameCtrl,
                autofocus: true,
                decoration: const InputDecoration(
                    labelText: 'Come lo chiami?', hintText: 'es. Marco'),
              ),
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('No')),
            FilledButton(
              onPressed: () {
                final name = nameCtrl.text.trim();
                try {
                  store.pairContact(name.isEmpty ? 'Amico' : name, cardB64);
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text(
                          'Aggiunto! Ora puoi scrivergli dalla scheda Contatti.')));
                } catch (e) {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context)
                      .showSnackBar(SnackBar(content: Text('Errore: $e')));
                }
              },
              child: const Text('Aggiungi'),
            ),
          ],
        ),
      );
    });
  }

  void _showSas(BuildContext context) {
    final String sas;
    try {
      sas = store.fingerprintFor(contact);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Codice non disponibile: $e')));
      return;
    }
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Codice di sicurezza'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
                'Confronta questo codice con quello che vede il tuo amico, '
                'di persona o al telefono. Se è uguale, nessuno vi sta '
                'spiando.'),
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
            child: const Text('I codici coincidono'),
          ),
        ],
      ),
    );
  }
}
