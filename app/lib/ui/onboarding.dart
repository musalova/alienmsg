import 'package:flutter/material.dart';

import '../api.dart';
import '../logo.dart';
import '../store.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _restoreCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _restoreCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  /// One-tap registration: identity generated internally, vault bound to this
  /// device. Nothing to write down or remember.
  Future<void> _create() async {
    setState(() => _busy = true);
    try {
      await store.createIdentitySimple();
      await store.bindDevice();
    } catch (_) {
      if (mounted) setState(() => _error = 'Qualcosa è andato storto. Riprova.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _restore() async {
    final phrase = _restoreCtrl.text.trim();
    if (!AlienApi.validateMnemonic(phrase)) {
      setState(() => _error = 'Frase non valida (checksum errato)');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      store.createIdentity(phrase, _passCtrl.text);
      await store.bindDevice();
    } catch (_) {
      if (mounted) setState(() => _error = 'Qualcosa è andato storto. Riprova.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560),
            child: ListView(
              padding: const EdgeInsets.all(24),
              shrinkWrap: true,
              children: [
                const AlienLogo(size: 88),
                const SizedBox(height: 16),
                Text('AlienMsg',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 8),
                Text(
                  'Messaggi che nessuno può leggere.\nLi incolli in qualsiasi app: SMS, chat, email.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const SizedBox(height: 32),
                FilledButton.icon(
                  style:
                      FilledButton.styleFrom(padding: const EdgeInsets.all(16)),
                  onPressed: _busy ? null : _create,
                  icon: const Icon(Icons.add),
                  label: Text(
                      _busy ? 'Creazione in corso…' : 'Inizia — crea il tuo profilo',
                      style: const TextStyle(fontSize: 16)),
                ),
                const SizedBox(height: 8),
                Text(
                  'Il profilo resta su questo dispositivo, protetto dal sistema.\n'
                  'Potrai aggiungere un PIN o l\'impronta dalle Impostazioni.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                if (_error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(_error!,
                        textAlign: TextAlign.center,
                        style: TextStyle(
                            color: Theme.of(context).colorScheme.error)),
                  ),
                const SizedBox(height: 24),
                ExpansionTile(
                  tilePadding: EdgeInsets.zero,
                  title: const Text('Opzioni avanzate'),
                  children: [
                    const SizedBox(height: 4),
                    Text('Ripristina da frase di recupero',
                        style: Theme.of(context).textTheme.titleSmall),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _restoreCtrl,
                      maxLines: 3,
                      decoration: const InputDecoration(
                        border: OutlineInputBorder(),
                        hintText: 'Le 24 parole separate da spazi…',
                      ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _passCtrl,
                      obscureText: true,
                      decoration: const InputDecoration(
                        border: OutlineInputBorder(),
                        labelText: 'Parola extra (se la usavi)',
                        helperText: 'Senza di essa otterrai un profilo DIVERSO',
                      ),
                    ),
                    const SizedBox(height: 8),
                    OutlinedButton(
                      onPressed: _busy ? null : _restore,
                      child: const Text('Ripristina'),
                    ),
                    const SizedBox(height: 8),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
