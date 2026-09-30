import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../api.dart';
import '../store.dart';
import '../main.dart' show copyToClipboard;
import 'peer_screen.dart';
import 'group_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: store,
      builder: (_, __) => Scaffold(
        appBar: AppBar(title: const Text('AlienMsg')),
        body: [
          const ContactsTab(),
          const GroupsTab(),
          const SettingsTab(),
        ][_tab],
        bottomNavigationBar: NavigationBar(
          selectedIndex: _tab,
          onDestinationSelected: (i) => setState(() => _tab = i),
          destinations: const [
            NavigationDestination(icon: Icon(Icons.people), label: 'Contatti'),
            NavigationDestination(icon: Icon(Icons.groups), label: 'Gruppi'),
            NavigationDestination(
                icon: Icon(Icons.settings), label: 'Impostazioni'),
          ],
        ),
      ),
    );
  }
}

class ContactsTab extends StatelessWidget {
  const ContactsTab({super.key});

  Future<void> _addContact(BuildContext context) async {
    final nameCtrl = TextEditingController();
    final cardCtrl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Abbina contatto'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(labelText: 'Nome'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: cardCtrl,
              maxLines: 4,
              decoration: const InputDecoration(
                labelText: 'Carta contatto del peer',
                hintText: 'Incolla qui la sua carta (AYA1:…)',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Annulla')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Abbina')),
        ],
      ),
    );
    if (ok != true || !context.mounted) return;
    try {
      // decode the pasted card through the inbound pipeline (verifies signature)
      final envB64 = AlienApi.unrender(cardCtrl.text.trim());
      final r = AlienApi.decrypt(
        identityB64: store.identitySeed!,
        bundlesB64: store.bundles,
        sessionsB64: const [],
        groupsB64: const [],
        envelopeB64: envB64,
      );
      if (r['kind'] != 'card') throw const FormatException('non è una carta');
      store.pairContact(nameCtrl.text.trim(), r['card'] as String);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
            content: Text('Contatto abbinato — invia il primo messaggio')));
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }

  void _showMyCard(BuildContext context) {
    final cardText = store.shareCard();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('La tua carta contatto'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                  'Falla arrivare al peer (incolla o QR di persona). Serve una '
                  'carta diversa per ogni contatto.'),
              const SizedBox(height: 12),
              SizedBox(
                width: 220,
                height: 220,
                child: QrImageView(data: cardText, version: QrVersions.auto),
              ),
              const SizedBox(height: 8),
              SelectableText(cardText,
                  maxLines: 4,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 10)),
              const SizedBox(height: 4),
              Text('La QR contiene la stessa carta (densa, ML-KEM-1024).',
                  style: Theme.of(ctx).textTheme.bodySmall),
            ],
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Chiudi')),
          FilledButton.icon(
            onPressed: () => copyToClipboard(ctx, cardText, 'Carta copiata'),
            icon: const Icon(Icons.copy),
            label: const Text('Copia'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = store.contacts;
    return Scaffold(
      body: cs.isEmpty
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(24),
                child: Text(
                    'Nessun contatto.\nAbbina scambiando le carte contatto.'),
              ),
            )
          : ListView.builder(
              itemCount: cs.length,
              itemBuilder: (_, i) {
                final c = cs[i];
                return ListTile(
                  leading: Icon(c.verified
                      ? Icons.verified_user
                      : Icons.person_outline),
                  title: Text(c.name),
                  subtitle: Text(
                    c.session != null
                        ? 'Abbinato · ${c.pubId.substring(0, 12)}…'
                        : 'Da abbinare · ${c.pubId.substring(0, 12)}…',
                  ),
                  onTap: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                        builder: (_) => PeerScreen(contact: c)),
                  ),
                );
              },
            ),
      floatingActionButton: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          FloatingActionButton.small(
            heroTag: 'mycard',
            onPressed: () => _showMyCard(context),
            child: const Icon(Icons.badge_outlined),
          ),
          const SizedBox(height: 8),
          FloatingActionButton(
            heroTag: 'add',
            onPressed: () => _addContact(context),
            child: const Icon(Icons.person_add),
          ),
        ],
      ),
    );
  }
}

class GroupsTab extends StatelessWidget {
  const GroupsTab({super.key});

  Future<void> _createGroup(BuildContext context) async {
    final paired =
        store.contacts.where((c) => c.session != null).toList();
    if (paired.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Abbina prima almeno un contatto')));
      return;
    }
    final nameCtrl = TextEditingController();
    final selected = <String>{};
    final invite = await showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          title: const Text('Nuovo gruppo'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameCtrl,
                decoration: const InputDecoration(labelText: 'Nome gruppo'),
              ),
                const SizedBox(height: 12),
              ...paired.map((c) => CheckboxListTile(
                    dense: true,
                    title: Text(c.name),
                    value: selected.contains(c.pubId),
                    onChanged: (v) => setD(() => v == true
                        ? selected.add(c.pubId)
                        : selected.remove(c.pubId)),
                  )),
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Annulla')),
            FilledButton(
              onPressed: () {
                try {
                  final invite = store.createGroup(
                      nameCtrl.text.trim().isEmpty
                          ? 'Gruppo'
                          : nameCtrl.text.trim(),
                      selected.toList());
                  Navigator.pop(ctx, invite);
                } catch (e) {
                  Navigator.pop(ctx, 'ERR:$e');
                }
              },
              child: const Text('Crea'),
            ),
          ],
        ),
      ),
    );
    if (invite == null || !context.mounted) return;
    if (invite.startsWith('ERR:')) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(invite.substring(4))));
      return;
    }
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Invito gruppo'),
        content: const Text(
            'Incolla questo blob nel canale del gruppo: ogni membro decifrerà '
            'la propria copia della chiave.'),
        actions: [
          FilledButton.icon(
            onPressed: () {
              copyToClipboard(ctx, invite, 'Invito copiato');
              Navigator.pop(ctx);
            },
            icon: const Icon(Icons.copy),
            label: const Text('Copia invito'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final gs = store.groups;
    return Scaffold(
      body: gs.isEmpty
          ? const Center(child: Text('Nessun gruppo.'))
          : ListView.builder(
              itemCount: gs.length,
              itemBuilder: (_, i) => ListTile(
                leading: const Icon(Icons.groups),
                title: Text(gs[i].name),
                subtitle: Text(gs[i].groupId.substring(0, 12)),
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(
                      builder: (_) => GroupScreen(group: gs[i])),
                ),
              ),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _createGroup(context),
        child: const Icon(Icons.group_add),
      ),
    );
  }
}

class SettingsTab extends StatelessWidget {
  const SettingsTab({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const ListTile(
          leading: Icon(Icons.fingerprint),
          title: Text('Identità pubblica'),
          subtitle: Text('Identificativo derivato dalle tue chiavi'),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: SelectableText(store.pubId ?? '-',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
        ),
        const Divider(height: 32),
        const ListTile(
          leading: Icon(Icons.shield_outlined),
          title: Text('Crittografia'),
          subtitle: Text(
              'X25519 + ML-KEM-1024 (post-quantum) · Double Ratchet · '
              'XChaCha20-Poly1305 · Ed25519'),
        ),
        const ListTile(
          leading: Icon(Icons.warning_amber),
          title: Text('Verifica i contatti'),
          subtitle: Text(
              'Confronta il codice di sicurezza di persona per escludere '
              'intercettazioni sul canale di scambio.'),
        ),
        const SizedBox(height: 24),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.error),
            onPressed: () async {
              final ok = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Cancellare tutto?'),
                  content: const Text(
                      'Chiavi di sessione, contatti e gruppi verranno rimossi. '
                      'Solo la frase di recupero può ripristinare l\'identità.'),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: const Text('Annulla')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, true),
                        child: const Text('Cancella')),
                  ],
                ),
              );
              if (ok == true) store.wipe();
            },
            icon: const Icon(Icons.delete_forever),
            label: const Text('Cancella dati (chiudi vault)'),
          ),
        ),
      ],
    );
  }
}
