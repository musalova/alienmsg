import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';

/// Lightweight self-update: polls a JSON manifest for the latest release and
/// offers to download it. The manifest URL is compiled in; it points at the
/// repo's `updates/latest.json` (or any HTTPS endpoint you host).
///
/// Manifest format:
///   {"version": "1.2.0", "url": "https://…/alienmsg-1.2.0.apk",
///    "notes": "…", "mandatory": false}
///
/// The check is silent on any error (offline-first app: no update server, no
/// problem).
class UpdateChecker {
  UpdateChecker._();

  /// Edit to point at your update manifest. Empty disables the feature.
  static const manifestUrl =
      'https://alienmsg.example.com/updates/latest.json';

  static Future<UpdateInfo?> check() async {
    // The PWA is always current: the service worker serves the newest build
    // on reload. Only native builds need a manifest-driven update flow.
    if (kIsWeb || manifestUrl.isEmpty) return null;
    try {
      final res = await http
          .get(Uri.parse(manifestUrl))
          .timeout(const Duration(seconds: 6));
      if (res.statusCode != 200) return null;
      final body = res.body;
      final m = jsonDecode(body) as Map<String, dynamic>;
      final latest = m['version'] as String?;
      if (latest == null) return null;
      final info = await PackageInfo.fromPlatform();
      if (_isNewer(latest, info.version)) {
        return UpdateInfo(
          version: latest,
          url: m['url'] as String? ?? '',
          notes: m['notes'] as String? ?? '',
          mandatory: m['mandatory'] == true,
        );
      }
    } catch (_) {
      // Offline or no manifest → silently skip. Updates are a nicety,
      // never a boot blocker.
    }
    return null;
  }

  static bool _isNewer(String latest, String current) {
    List<int> v(String s) => s
        .split(RegExp(r'[.-]'))
        .map((p) => int.tryParse(p) ?? 0)
        .toList();
    final a = v(latest), b = v(current);
    for (var i = 0; i < 3; i++) {
      final x = i < a.length ? a[i] : 0;
      final y = i < b.length ? b[i] : 0;
      if (x != y) return x > y;
    }
    return false;
  }

  /// Show the update dialog when a newer version exists. Called from the
  /// home screen after boot; [mandatory] versions can't be dismissed.
  static Future<void> promptIfNeeded(BuildContext context) async {
    final info = await check();
    if (info == null || !context.mounted) return;
    await showDialog(
      context: context,
      barrierDismissible: !info.mandatory,
      builder: (ctx) => AlertDialog(
        title: Text('Nuova versione ${info.version}'),
        content: Text(
            '${info.notes.isEmpty ? 'È disponibile un aggiornamento di AlienMsg.' : info.notes}\n\nScaricalo per avere gli ultimi miglioramenti di sicurezza.'),
        actions: [
          if (!info.mandatory)
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Dopo')),
          FilledButton.icon(
            onPressed: () {
              launchUrl(Uri.parse(info.url),
                  mode: LaunchMode.externalApplication);
              if (!info.mandatory) Navigator.pop(ctx);
            },
            icon: const Icon(Icons.download),
            label: const Text('Aggiorna'),
          ),
        ],
      ),
    );
  }
}

class UpdateInfo {
  const UpdateInfo(
      {required this.version,
      required this.url,
      required this.notes,
      required this.mandatory});
  final String version, url, notes;
  final bool mandatory;
}
