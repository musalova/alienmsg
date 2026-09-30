import 'package:flutter/material.dart';

import '../api.dart';
import '../store.dart';
import '../main.dart' show copyToClipboard;
import 'widgets.dart';

class GroupScreen extends StatelessWidget {
  final GroupChat group;
  const GroupScreen({super.key, required this.group});

  @override
  Widget build(BuildContext context) {
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
      body: CryptoPanel(
        onEncrypt: (pt, fmt) => store.encryptGroup(group, pt, fmt),
        onDecrypt: (input) {
          final r = store.processInbound(input);
          return switch (r.kind) {
            'group_text' => '[${(r.peerId ?? '?').substring(0, 8)}] ${r.text}',
            'text' => r.text,
            _ => r.text,
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
    final isAdmin = members.any((m) => m['is_me'] == true && m['is_admin'] == true);
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Membri — epoch ${info['epoch']}'),
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
                  subtitle: Text((m['id'] as String).substring(0, 16)),
                  trailing: (isAdmin && m['is_me'] != true)
                      ? IconButton(
                          icon: const Icon(Icons.remove_circle_outline),
                          onPressed: () => _removeMember(ctx, m['id'] as String,
                              members.map((x) => x['id'] as String).toList()),
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
    return 'Membro ${pubId.substring(0, 8)}';
  }

  Future<void> _removeMember(
      BuildContext dialogCtx, String removeId, List<String> all) async {
    try {
      final keep = all.where((id) => id != removeId).toList();
      final blob = store.rotateGroup(group, keep);
      if (dialogCtx.mounted) {
        Navigator.pop(dialogCtx);
        await showDialog(
          context: dialogCtx,
          builder: (ctx2) => AlertDialog(
            title: const Text('Chiave ruotata'),
            content: const Text(
                'Incolla questo blob nel gruppo: i membri rimasti passeranno '
                'alla nuova epoch. Chi è stato rimosso non leggerà più.'),
            actions: [
              FilledButton.icon(
                onPressed: () {
                  copyToClipboard(ctx2, blob, 'Blob rotazione copiato');
                  Navigator.pop(ctx2);
                },
                icon: const Icon(Icons.copy),
                label: const Text('Copia rotazione'),
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
