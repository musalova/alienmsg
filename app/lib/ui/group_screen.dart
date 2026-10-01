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
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Chiudi')),
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

  Future<void> _removeMember(
      BuildContext dialogCtx, String removeId, List<String> all) async {
    try {
      final keep = all.where((id) => id != removeId).toList();
      final blob = store.rotateGroup(group, keep);
      bool copied = true;
      try {
        Clipboard.setData(ClipboardData(text: blob));
      } catch (_) {
        copied = false; // web clipboard can be denied: show the code instead
      }
      if (dialogCtx.mounted) {
        Navigator.pop(dialogCtx);
        await showDialog(
          context: dialogCtx,
          builder: (ctx2) => AlertDialog(
            title: const Text('Membro rimosso'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(copied
                    ? 'Ho copiato un codice di aggiornamento: incollalo nel '
                        'gruppo. Gli altri membri passeranno alle nuove '
                        'chiavi e chi è uscito non potrà più leggere.'
                    : 'Incolla questo codice di aggiornamento nel gruppo: '
                        'gli altri membri passeranno alle nuove chiavi e chi '
                        'è uscito non potrà più leggere.'),
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
                onPressed: () =>
                    copyToClipboard(ctx2, blob, 'Codice copiato'),
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
    } catch (e) {
      if (dialogCtx.mounted) {
        ScaffoldMessenger.of(dialogCtx)
            .showSnackBar(SnackBar(content: Text('Errore: $e')));
      }
    }
  }
}
