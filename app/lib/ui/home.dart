import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../api.dart';
import '../logo.dart';
import '../store.dart';
import '../main.dart' show copyToClipboard;
import 'chat_panel.dart' show looksLikeCode;
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
        appBar: AppBar(
          title: const Row(
            children: [
              AlienLogo(size: 30, showBackground: false),
              SizedBox(width: 10),
              Text('AlienMsg'),
            ],
          ),
        ),
        body: Column(
          children: [
            if (store.persistFailed)
              MaterialBanner(
                backgroundColor: Theme.of(context).colorScheme.errorContainer,
                content: const Text(
                    'Spazio esaurito — i nuovi messaggi potrebbero non essere '
                    'salvati. Elimina qualche chat o libera spazio.'),
                actions: [
                  TextButton(
                    onPressed: store.acknowledgePersistFailure,
                    child: const Text('OK'),
                  ),
                ],
              ),
            if (store.recoveryPhrase != null && !store.backupDismissed)
              MaterialBanner(
                leading: const Icon(Icons.key_outlined),
                content: const Text(
                    'Se perdi questo dispositivo perdi il profilo. Salva la '
                    'frase di recupero?'),
                actions: [
                  TextButton(
                    onPressed: store.dismissBackupReminder,
                    child: const Text('Dopo'),
                  ),
                  FilledButton(
                    onPressed: () {
                      store.dismissBackupReminder();
                      showRecoveryDialog(context);
                    },
                    child: const Text('Salva ora'),
                  ),
                ],
              ),
            Expanded(
              child: [
                const ContactsTab(),
                const GroupsTab(),
                const SettingsTab(),
              ][_tab],
            ),
          ],
        ),
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
    // If the friend already sent their code, it's probably in the clipboard:
    // pre-fill the field so the user only has to press one button.
    try {
      final clip = await Clipboard.getData(Clipboard.kTextPlain);
      final t = clip?.text?.trim() ?? '';
      if (looksLikeCode(t)) cardCtrl.text = t;
    } catch (_) {}
    if (!context.mounted) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Aggiungi un amico'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(
                  labelText: 'Come lo chiami?', hintText: 'es. Marco'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: cardCtrl,
              maxLines: 4,
              decoration: const InputDecoration(
                labelText: 'Codice del tuo amico',
                hintText: 'Incolla qui il codice che ti ha mandato',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                icon: const Icon(Icons.content_paste, size: 18),
                label: const Text('Incolla dagli appunti'),
                onPressed: () async {
                  final d =
                      await Clipboard.getData(Clipboard.kTextPlain);
                  cardCtrl.text = d?.text ?? '';
                },
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
              child: const Text('Aggiungi')),
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
      if (r['kind'] != 'card') {
        // Not a card — could be a PairInit or message envelope pasted here.
        // Route it through the full inbound pipeline instead of dropping it.
        final res = store.processInbound(cardCtrl.text.trim());
        if (context.mounted) {
          ScaffoldMessenger.of(context)
              .showSnackBar(SnackBar(content: Text(res.text)));
        }
        return;
      }
      final name = nameCtrl.text.trim();
      store.pairContact(name.isEmpty ? 'Amico' : name, r['card'] as String);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
            content: Text(
                'Collegato! Scrivigli il primo messaggio per attivare il canale sicuro.')));
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }

  Future<void> _confirmDeleteContact(BuildContext context, Contact c) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Eliminare ${c.name}?'),
        content: const Text(
            'Il contatto e le chiavi di conversazione verranno rimossi. '
            'Per riscrivervi servirà un nuovo scambio di codici.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Annulla')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Elimina')),
        ],
      ),
    );
    if (ok == true) store.deleteContact(c);
  }

  void _showMyCard(BuildContext context) {
    final cardText = store.shareCard();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Il tuo codice'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                  'Mandalo al tuo amico o fagli inquadrare il QR di persona. '
                  'Serve un codice diverso per ogni amico.'),
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
              Text('Il QR contiene lo stesso codice.',
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
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 340),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Text('Per iniziare:', textAlign: TextAlign.center,
                          style: TextStyle(fontWeight: FontWeight.bold)),
                      const SizedBox(height: 16),
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.tonalIcon(
                          onPressed: () => _showMyCard(context),
                          icon: const Icon(Icons.qr_code),
                          label: const Text('1. Mostra il tuo codice'),
                        ),
                      ),
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 8),
                        child: Text('oppure, se l\'amico ti ha già scritto',
                            textAlign: TextAlign.center),
                      ),
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.tonalIcon(
                          onPressed: () => _addContact(context),
                          icon: const Icon(Icons.person_add),
                          label: const Text('2. Incolla il suo codice'),
                        ),
                      ),
                    ],
                  ),
                ),
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
                        ? (c.verified ? 'Verificato · sicuro' : 'Collegato')
                        : 'Da collegare',
                  ),
                  onTap: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                        builder: (_) => PeerScreen(contact: c)),
                  ),
                  onLongPress: () => _confirmDeleteContact(context, c),
                );
              },
            ),
      floatingActionButton: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          FloatingActionButton.small(
            heroTag: 'mycard',
            tooltip: 'Il tuo codice',
            onPressed: () => _showMyCard(context),
            child: const Icon(Icons.qr_code),
          ),
          const SizedBox(height: 8),
          FloatingActionButton(
            heroTag: 'add',
            tooltip: 'Aggiungi un amico',
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
          content: Text('Aggiungi prima almeno un amico')));
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
    bool copied = true;
    try {
      Clipboard.setData(ClipboardData(text: invite));
    } catch (_) {
      copied = false; // Safari/web can deny clipboard: show it instead
    }
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Gruppo creato'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(copied
                ? 'Ho copiato l\'invito: incollalo nella chat con i tuoi '
                    'amici. Chi lo riceve entra automaticamente.'
                : 'Incolla questo invito nella chat con i tuoi amici. Chi lo '
                    'riceve entra automaticamente.'),
            const SizedBox(height: 12),
            Container(
              constraints: const BoxConstraints(maxHeight: 120),
              child: SingleChildScrollView(
                child: SelectableText(invite,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 10)),
              ),
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: () => copyToClipboard(ctx, invite, 'Invito copiato'),
            icon: const Icon(Icons.copy, size: 18),
            label: const Text('Copia'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Fatto'),
          ),
        ],
      ),
    );
  }

  Future<void> _confirmDeleteGroup(BuildContext context, GroupChat g) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Uscire da "${g.name}"?'),
        content: const Text(
            'Il gruppo viene rimosso solo localmente. Chiedi all\'admin una '
            'rotazione delle chiavi per revocare davvero l\'accesso.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Annulla')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Rimuovi')),
        ],
      ),
    );
    if (ok == true) store.deleteGroup(g);
  }

  @override
  Widget build(BuildContext context) {
    final gs = store.groups;
    return Scaffold(
      body: gs.isEmpty
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(24),
                child: Text('Nessun gruppo.\nTocca + per crearne uno.',
                    textAlign: TextAlign.center),
              ),
            )
          : ListView.builder(
              itemCount: gs.length,
              itemBuilder: (_, i) => ListTile(
                leading: const Icon(Icons.groups),
                title: Text(gs[i].name),
                subtitle: const Text('Tocca per aprire'),
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(
                      builder: (_) => GroupScreen(group: gs[i])),
                ),
                onLongPress: () => _confirmDeleteGroup(context, gs[i]),
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

  Future<void> _lockModeDialog(BuildContext context) async {
    // Windows Hello / biometric availability depends on the device; local_auth
    // has no web implementation, so on the web build only PIN/none are offered.
    bool helloOk = false;
    if (!kIsWeb) {
      try {
        helloOk = await LocalAuthentication().isDeviceSupported();
      } catch (_) {}
    }
    if (!context.mounted) return;

    final pinCtrl = TextEditingController();
    final confirmCtrl = TextEditingController();
    String mode = store.lockMode ?? 'none';
    final result = await showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          title: const Text('Blocco app'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                  'Il profilo è già legato a questo dispositivo. Puoi aggiungere '
                  'un controllo ad ogni avvio.'),
              const SizedBox(height: 12),
              RadioGroup<String>(
                groupValue: mode,
                onChanged: (v) => setD(() => mode = v!),
                child: const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    RadioListTile<String>(
                      value: 'none',
                      title: Text('Nessuno'),
                      subtitle: Text('Si apre subito'),
                    ),
                    RadioListTile<String>(
                      value: 'pin',
                      title: Text('PIN'),
                      subtitle:
                          Text('Una sequenza di cifre ad ogni avvio'),
                    ),
                  ],
                ),
              ),
              RadioGroup<String>(
                groupValue: mode,
                onChanged: (v) {
                  if (helloOk) setD(() => mode = v ?? 'none');
                },
                child: const RadioListTile<String>(
                  value: 'hello',
                  title: Text('Impronta / Windows Hello'),
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(left: 16),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                      helloOk
                          ? 'Verifica di Windows ad ogni avvio'
                          : 'Impronta / Windows Hello non disponibile su questo dispositivo',
                      style: Theme.of(ctx).textTheme.bodySmall),
                ),
              ),
              if (mode == 'pin') ...[
                TextField(
                  controller: pinCtrl,
                  obscureText: true,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                      labelText: 'Nuovo PIN', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: confirmCtrl,
                  obscureText: true,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                      labelText: 'Conferma PIN', border: OutlineInputBorder()),
                ),
              ],
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Annulla')),
            FilledButton(
              onPressed: () {
                if (mode == 'pin') {
                  if (pinCtrl.text.length < 4) {
                    Navigator.pop(ctx, 'ERR:PIN troppo corto (min 4 cifre)');
                    return;
                  }
                  if (pinCtrl.text != confirmCtrl.text) {
                    Navigator.pop(ctx, 'ERR:I PIN non coincidono');
                    return;
                  }
                  Navigator.pop(ctx, 'PIN:${pinCtrl.text}');
                  return;
                }
                Navigator.pop(ctx, mode);
              },
              child: const Text('Salva'),
            ),
          ],
        ),
      ),
    );
    if (result == null || !context.mounted) return;
    if (result.startsWith('ERR:')) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(result.substring(4))));
      return;
    }
    try {
      if (result.startsWith('PIN:')) {
        await store.setPin(result.substring(4));
      } else if (result == 'hello') {
        await store.setHello(true);
      } else {
        await store.setHello(false);
        await store.setPin(null);
      }
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Impostazione salvata')));
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const ListTile(
          leading: Icon(Icons.fingerprint),
          title: Text('La tua identità'),
          subtitle: Text('Il tuo codice identificativo pubblico'),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: SelectableText(store.pubId ?? '-',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
        ),
        const Divider(height: 32),
        const ListTile(
          leading: Icon(Icons.shield_outlined),
          title: Text('Protezione massima attiva'),
          subtitle: Text(
              'Crittografia post-quantum: nemmeno i computer quantistici '
              'potranno leggere i tuoi messaggi.'),
        ),
        const ListTile(
          leading: Icon(Icons.warning_amber),
          title: Text('Consiglio di sicurezza'),
          subtitle: Text(
              'Confronta il codice di sicurezza col tuo amico di persona '
              '(icona 🔑 in alto nella chat): se è uguale, nessuno vi spia.'),
        ),
        const Divider(height: 32),
        ListTile(
          leading: const Icon(Icons.devices),
          title: const Text('Profilo legato a questo dispositivo'),
          subtitle: Text(switch (store.lockMode) {
            'pin' =>
              'Il vault è cifrato e protetto dal tuo PIN: senza di esso non si apre.',
            _ => kIsWeb
                ? 'Il vault è cifrato e legato a questo browser.'
                : 'Il vault è cifrato e legato a questo dispositivo: una copia del file non si apre altrove.',
          }),
        ),
        ListTile(
          leading: Icon(switch (store.lockMode) {
            'pin' => Icons.pin,
            'hello' => Icons.fingerprint,
            _ => Icons.lock_open_outlined,
          }),
          title: const Text('Blocco app'),
          subtitle: Text(switch (store.lockMode) {
            'pin' => 'PIN richiesto ad ogni avvio',
            'hello' => 'Impronta / Windows Hello ad ogni avvio',
            _ => 'Nessuno — si apre subito',
          }),
          onTap: () => _lockModeDialog(context),
        ),
        ListTile(
          leading: const Icon(Icons.key_outlined),
          title: const Text('Frase di recupero'),
          subtitle: const Text(
              'Backup opzionale per spostare il profilo su un altro dispositivo'),
          onTap: () => showRecoveryDialog(context),
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
                      'Contatti, gruppi e chiavi verranno cancellati per '
                      'sempre. Potrai ripartire solo con la frase di '
                      'recupero.'),
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
              if (ok == true) await store.wipe();
            },
            icon: const Icon(Icons.delete_forever),
            label: const Text('Cancella tutto'),
          ),
        ),
      ],
    );
  }
}

/// Recovery-phrase dialog — shared by the settings tile and the one-time
/// backup reminder banner on the home screen.
void showRecoveryDialog(BuildContext context) {
  final phrase = store.recoveryPhrase;
  showDialog(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Text('Frase di recupero'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
              'Scrivila su un foglio e conservala in un posto sicuro: è '
              'l\'unico modo per recuperare il profilo se perdi questo '
              'dispositivo. Non serve per l\'uso quotidiano.'),
          const SizedBox(height: 12),
          if (phrase != null)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                border: Border.all(color: Colors.white24),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(phrase,
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 14, height: 1.5)),
            )
          else
            const Text('Nessuna frase salvata per questo profilo.'),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(ctx), child: const Text('Chiudi')),
        if (phrase != null)
          FilledButton.icon(
            onPressed: () => copyToClipboard(context, phrase, 'Frase copiata'),
            icon: const Icon(Icons.copy),
            label: const Text('Copia'),
          ),
      ],
    ),
  );
}
