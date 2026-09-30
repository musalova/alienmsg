import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'ffi.dart';
import 'store.dart';
import 'ui/onboarding.dart';
import 'ui/home.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  AlienFfi.init();
  final path = await Store.defaultVaultPath();
  // Vault opens with an empty password: the vault key is random and the file
  // stays encrypted at rest. An app-level passphrase lock can be layered on
  // top later without changing the vault format.
  await store.open(path, '');
  runApp(const AlienApp());
}

class AlienApp extends StatelessWidget {
  const AlienApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AlienMsg',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        colorSchemeSeed: const Color(0xFF7C4DFF),
        useMaterial3: true,
        snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
      ),
      home: AnimatedBuilder(
        animation: store,
        builder: (_, __) =>
            store.hasIdentity ? const HomeScreen() : const OnboardingScreen(),
      ),
    );
  }
}

/// Copy helper used across screens.
void copyToClipboard(BuildContext context, String text, [String? label]) {
  Clipboard.setData(ClipboardData(text: text));
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text(label ?? 'Copiato negli appunti')),
  );
}
