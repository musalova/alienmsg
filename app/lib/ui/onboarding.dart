import 'package:flutter/material.dart';

import '../api.dart';
import '../store.dart';
import '../main.dart' show copyToClipboard;

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  String? _mnemonic;
  final _restoreCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _confirmed = false;
  String? _error;

  @override
  void dispose() {
    _restoreCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    final m = await AlienApi.generateMnemonic();
    setState(() => _mnemonic = m);
  }

  void _create() {
    if (_mnemonic == null || !_confirmed) return;
    store.createIdentity(_mnemonic!, _passCtrl.text);
  }

  void _restore() {
    final phrase = _restoreCtrl.text.trim();
    if (!AlienApi.validateMnemonic(phrase)) {
      setState(() => _error = 'Frase non valida (checksum errato)');
      return;
    }
    store.createIdentity(phrase, _passCtrl.text);
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
                const Icon(Icons.lock_outline, size: 56),
                const SizedBox(height: 12),
                Text('AlienMsg',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 8),
                Text(
                  'Cifratura end-to-end post-quantum.\nI messaggi si incollano in qualsiasi app.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const SizedBox(height: 32),
                if (_mnemonic == null) ...[
                  FilledButton.icon(
                    onPressed: _generate,
                    icon: const Icon(Icons.add),
                    label: const Text('Genera nuova identità'),
                  ),
                  const SizedBox(height: 24),
                  const Divider(),
                  const SizedBox(height: 16),
                  Text('Ripristina da frase di recupero',
                      style: Theme.of(context).textTheme.titleSmall),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _restoreCtrl,
                    maxLines: 3,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      hintText: '24 parole separate da spazi…',
                    ),
                  ),
                  if (_error != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text(_error!,
                          style: TextStyle(
                              color: Theme.of(context).colorScheme.error)),
                    ),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: _restore,
                    child: const Text('Ripristina identità'),
                  ),
                ] else ...[
                  Text('La tua frase di recupero',
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 4),
                  const Text(
                      'Scrivila su carta e conservala al sicuro. Chi la possiede '
                      'controlla la tua identità. I messaggi passati restano '
                      'protetti dal forward secrecy.'),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      border: Border.all(color: Colors.white24),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: SelectableText(
                      _mnemonic!,
                      style: const TextStyle(
                          fontFamily: 'monospace', fontSize: 15, height: 1.6),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Row(children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () =>
                            copyToClipboard(context, _mnemonic!, 'Frase copiata'),
                        icon: const Icon(Icons.copy),
                        label: const Text('Copia frase'),
                      ),
                    ),
                  ]),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passCtrl,
                    obscureText: true,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      labelText: 'Parola extra opzionale (25ª parola)',
                      helperText: 'Rende la frase inutile a chi la trova',
                    ),
                  ),
                  CheckboxListTile(
                    value: _confirmed,
                    onChanged: (v) => setState(() => _confirmed = v ?? false),
                    title: const Text('Ho conservato la frase in sicurezza'),
                    controlAffinity: ListTileControlAffinity.leading,
                    contentPadding: EdgeInsets.zero,
                  ),
                  FilledButton.icon(
                    onPressed: _confirmed ? _create : null,
                    icon: const Icon(Icons.check),
                    label: const Text('Crea identità'),
                  ),
                  TextButton(
                    onPressed: () => setState(() => _mnemonic = null),
                    child: const Text('Indietro'),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
