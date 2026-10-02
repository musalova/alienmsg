import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api.dart';
import '../main.dart' show copyToClipboard;
import '../store.dart';
import 'chat_panel.dart';

class GroupScreen extends StatelessWidget {
  final GroupChat group;
  const GroupScreen({super.key, required this.group});

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: store,
      builder: (_, __) => _build(context),
    );
  }

  Widget _build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(group.name),
        actions: [
          IconButton(
            tooltip: 'Membri',
            icon: const Icon(Icons.people_outline),
            onPressed: () => _showMembers(context),
          ),
        ],
      ),
      body: ChatPanel(
        historyKey: Store.historyKeyForGroup(group.groupId),
        onSend: (pt, fmt) => store.encryptGroup(group, pt, fmt),
        onReceive: (input) {
          final r = store.processInbound(input);
          return switch (r.kind) {
            'group_text' =>
              ReceivedMsg(r.text, from: _memberLabel(r.peerId ?? '?')),
            'card' => const ReceivedMsg(
                'È il codice di un contatto — aggiungilo dalla scheda '
                'Contatti (pulsante 👤+).',
                system: true),
            'info' => ReceivedMsg(r.text, system: true),
            _ => ReceivedMsg(r.text),
          };
        },
      ),
    );
  }

  Future<void> _showMembers(BuildContext context) async {
    Map<String, dynamic> info;
    try {
      info = AlienApi.groupInfo(group.blob);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
      return;
    }
    final members = (info['members'] as List).cast<Map<String, dynamic>>();
    final isAdmin =
        members.any((m) => m['is_me'] == true && m['is_admin'] == true);
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Membri del gruppo'),
        content: SizedBox(
          width: 360,
          child: ListView(
            shrinkWrap: true,
            children: [
              for (final m in members)
                ListTile(
                  dense: true,
                  leading: Icon(m['is_admin'] == true
                      ? Icons.star_outline
                      : Icons.person_outline),
                  title: Text(_memberLabel(m['id'] as String)),
                  trailing: (isAdmin && m['is_me'] != true)
                      ? IconButton(
                          tooltip: 'Rimuovi dal gruppo',
                          icon: const Icon(Icons.remove_circle_outline),
                          onPressed: () => _removeMember(
                              context,
                              ctx,
                              m['id'] as String,
                              members
                                  .map((x) => x['id'] as String)
                                  .toList()),
                        )
                      : null,
                ),
            ],
          ),
        ),
        actions: [
          if (isAdmin)
            TextButton.icon(
              icon: const Icon(Icons.person_add_alt_1, size: 18),
              label: const Text('Aggiungi membro'),
              onPressed: () => _addMember(
                  context,
                  ctx,
                  members.map((x) => x['id'] as String).toList()),
            ),
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Chiudi')),
        ],
      ),
    );
  }

  /// Rotate the group key with [newMemberIds] added — under the hood the
  /// rotate envelope doubles as an invite for members with no group state.
  Future<void> _addMember(BuildContext screenCtx, BuildContext dialogCtx,
      List<String> memberIds) async {
    final candidates = store.contacts
        .where((c) => c.session != null && !memberIds.contains(c.pubId))
        .toList();
    if (candidates.isEmpty) {
      Navigator.pop(dialogCtx);
      ScaffoldMessenger.of(screenCtx).showSnackBar(const SnackBar(
          content: Text(
              'Nessun amico da aggiungere — collega prima un nuovo contatto.')));
      return;
    }
    final selected = <String>{};
    final ok = await showDialog<bool>(
      context: screenCtx,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          title: const Text('Aggiungi al gruppo'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              for (final c in candidates)
                CheckboxListTile(
                  dense: true,
                  title: Text(c.name),
                  value: selected.contains(c.pubId),
                  onChanged: (v) => setD(() => v == true
                      ? selected.add(c.pubId)
                      : selected.remove(c.pubId)),
                ),
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Annulla')),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Aggiungi'),
            ),
          ],
        ),
      ),
    );
    if (ok != true || selected.isEmpty || !screenCtx.mounted) return;
    try {
      final blob =
          store.rotateGroup(group, [...memberIds, ...selected]);
      Navigator.pop(dialogCtx); // close the members list
      await _shareRotate(screenCtx, blob,
          'Invito inviato: incolla il codice nella chat. I nuovi amici entrano '
          'automaticamente e tutti passano alle nuove chiavi.');
    } catch (e) {
      if (screenCtx.mounted) {
        ScaffoldMessenger.of(screenCtx)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }

  Future<void> _removeMember(BuildContext screenCtx, BuildContext dialogCtx,
      String removeId, List<String> all) async {
    try {
      final keep = all.where((id) => id != removeId).toList();
      final blob = store.rotateGroup(group, keep);
      Navigator.pop(dialogCtx);
      await _shareRotate(screenCtx, blob,
          'Gli altri membri passeranno alle nuove chiavi e chi è uscito non '
          'potrà più leggere.');
    } catch (e) {
      if (screenCtx.mounted) {
        ScaffoldMessenger.of(screenCtx)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }

  /// Copy the rotate/invite blob to the clipboard (with a visible fallback)
  /// and explain what to do with it.
  Future<void> _shareRotate(
      BuildContext ctx, String blob, String explanation) async {
    var copied = true;
    try {
      await Clipboard.setData(ClipboardData(text: blob));
    } catch (_) {
      copied = false; // web clipboard can be denied: show the code instead
    }
    if (!ctx.mounted) return;
    await showDialog(
      context: ctx,
      builder: (ctx2) => AlertDialog(
        title: const Text('Gruppo aggiornato'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(copied
                ? 'Ho copiato un codice di aggiornamento: incollalo nella '
                    'chat con i membri. $explanation'
                : 'Incolla questo codice di aggiornamento nella chat con i '
                    'membri. $explanation'),
            const SizedBox(height: 12),
            Container(
              constraints: const BoxConstraints(maxHeight: 120),
              child: SingleChildScrollView(
                child: SelectableText(blob,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 10)),
              ),
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: () => copyToClipboard(ctx2, blob, 'Codice copiato'),
            icon: const Icon(Icons.copy, size: 18),
            label: const Text('Copia'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx2),
            child: const Text('Fatto'),
          ),
        ],
      ),
    );
  }

  String _memberLabel(String pubId) {
    for (final c in store.contacts) {
      if (c.pubId == pubId) return c.name;
    }
    if (pubId == store.pubId) return 'Tu';
    if (pubId.length < 8) return 'Membro';
    return 'Membro ${pubId.substring(0, 8)}';
  }

}
