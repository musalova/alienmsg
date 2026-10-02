import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

import 'ffi.dart';
import 'plat.dart' as plat;
import 'store.dart';
import 'update.dart';
import 'ui/onboarding.dart';
import 'ui/home.dart';
import 'ui/splash.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
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
      home: const _Boot(),
    );
  }
}

/// Shows the animated splash while the FFI + vault boot in the background,
/// then switches to the right screen.
class _Boot extends StatefulWidget {
  const _Boot();

  @override
  State<_Boot> createState() => _BootState();
}

class _BootState extends State<_Boot> {
  bool _ready = false;
  bool _bootError = false;

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    final t0 = DateTime.now();
    try {
      await AlienFfi.init();
      await plat.secureReady(); // web: IndexedDB key + legacy migration
    } catch (_) {
      // WASM/native backend failed to load — the splash stays up with an
      // error rather than the app half-booting into broken crypto.
      if (mounted) setState(() => _bootError = true);
      return;
    }
    final path = await Store.defaultVaultPath();
    store.prepareVaultPath(path);

    // Device-bound vault: the sidecar either holds the vault password
    // (device-bound, opens transparently) or a `pin:`-wrapped blob that
    // cryptographically requires the user's PIN before the vault can open.
    String? devkey;
    try {
      devkey = await Store.devicePassword(path);
    } catch (_) {
      // Sidecar unreadable (vault copied from another device): legacy lock.
    }

    if (devkey != null && devkey.startsWith(Store.pinPrefix)) {
      store.needsPinToOpen = true;
      store.lockMode = 'pin';
    } else {
      try {
        await store.open(path, devkey ?? '');
        if (!store.isLocked && devkey == null && store.hasIdentity) {
          await store.bindDevice();
        }
      } on VaultLockedException {
        // Legacy password vault: LockScreen asks for the password.
      } catch (_) {
        // Any other open failure (storage broken, quota, wasm backend):
        // don't wedge on the splash forever — show the boot error.
        if (mounted) setState(() => _bootError = true);
        return;
      }
    }

    if (!store.isLocked && !store.needsPinToOpen) {
      store.lockMode = await Store.detectLockMode(path);
      if (store.lockMode != null) store.gate();
      // Web: another tab writing the vault would silently diverge state —
      // reload our in-memory copy instead.
      plat.onVaultChanged(() => store.reloadFromStorage());
    }

    // Keep the intro on screen long enough to read as an intro.
    final elapsed = DateTime.now().difference(t0);
    if (elapsed < const Duration(milliseconds: 1100)) {
      await Future.delayed(const Duration(milliseconds: 1100) - elapsed);
    }

    if (mounted) setState(() => _ready = true);

    // Check for updates once the UI is up (silent failure offline).
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && !store.isLocked && !store.isGated) {
        UpdateChecker.promptIfNeeded(context);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_bootError) {
      return const Scaffold(
        body: Center(
          child: Padding(
            padding: EdgeInsets.all(32),
            child: Text(
              'Impossibile caricare il motore crittografico.\nRicarica la pagina o riavvia l\'app.',
              textAlign: TextAlign.center,
            ),
          ),
        ),
      );
    }
    if (!_ready) return const SplashScreen();
    return AnimatedBuilder(
      animation: store,
      builder: (_, __) {
        if (store.isLocked) return const LockScreen();
        if (store.needsPinToOpen || store.isGated) return const GateScreen();
        return store.hasIdentity
            ? const HomeScreen()
            : const OnboardingScreen();
      },
    );
  }
}

/// Shown when the vault is password-bound. No secret is loaded until unlock.
class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _pwCtrl = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _unlock() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await store.unlock(_pwCtrl.text);
      // success: isLocked flips and AnimatedBuilder swaps in the real UI.
      // Register the multi-tab listener the boot path skipped while locked.
      plat.onVaultChanged(() => store.reloadFromStorage());
    } catch (_) {
      setState(() => _error = 'Password errata');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 340),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 56),
              const SizedBox(height: 16),
              Text('Vault protetto',
                  style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              const Text(
                'Inserisci la password del vault per continuare.\n\n'
                'Se hai spostato il profilo da un altro PC, la password è '
                'legata a quel dispositivo: cancella tutto e ripristina '
                'dalla frase di recupero.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 20),
              TextField(
                controller: _pwCtrl,
                obscureText: true,
                autofocus: true,
                enabled: !_busy,
                decoration: InputDecoration(
                  labelText: 'Password',
                  border: const OutlineInputBorder(),
                  errorText: _error,
                ),
                onSubmitted: (_) => _busy ? null : _unlock(),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: _busy ? null : _unlock,
                  icon: const Icon(Icons.lock_open),
                  label: const Text('Sblocca'),
                ),
              ),
              const SizedBox(height: 8),
              TextButton(
                onPressed: _busy ? null : () => _wipeAndRestore(context),
                child: const Text('Cancella e riparti dalla frase di recupero',
                    style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _wipeAndRestore(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Cancellare il vault?'),
        content: const Text(
            'I dati su questo dispositivo verranno eliminati. Potrai '
            'ripristinare il profilo solo se hai la frase di recupero.'),
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
  }

  @override
  void dispose() {
    _pwCtrl.dispose();
    super.dispose();
  }
}

/// App gate: vault is already open (device-bound); this only authenticates
/// the person with PIN or Windows Hello before showing the UI.
class GateScreen extends StatefulWidget {
  const GateScreen({super.key});

  @override
  State<GateScreen> createState() => _GateScreenState();
}

class _GateScreenState extends State<GateScreen> {
  final _pinCtrl = TextEditingController();
  String? _error;
  int _fails = 0;
  bool _waiting = false;
  bool _helloRunning = false;

  @override
  void initState() {
    super.initState();
    // local_auth has no web implementation: 'hello' can only ever be set on
    // native, but guard anyway so a migrated lockMode never calls it.
    if (!kIsWeb && store.lockMode == 'hello') {
      WidgetsBinding.instance
          .addPostFrameCallback((_) => _helloAuth());
    }
  }

  Future<void> _helloAuth() async {
    if (_helloRunning) return;
    setState(() {
      _helloRunning = true;
      _error = null;
    });
    try {
      final ok = await LocalAuthentication().authenticate(
        localizedReason: 'Sblocca AlienMsg',
      );
      if (ok) {
        store.ungate();
      } else if (mounted) {
        setState(() => _error = 'Accesso annullato');
      }
    } catch (_) {
      if (mounted) {
        setState(() => _error = 'Verifica del dispositivo non disponibile');
      }
    } finally {
      if (mounted) setState(() => _helloRunning = false);
    }
  }

  Future<void> _tryPin() async {
    if (_waiting) return;
    setState(() {
      _waiting = true;
      _error = null;
    });
    try {
      final ok = store.needsPinToOpen
          ? await _unlockPinFirst(_pinCtrl.text)
          : await store.checkPin(_pinCtrl.text);
      if (ok) {
        store.ungate();
        return;
      }
      _fails++;
      // Exponential backoff against brute force (in-memory per session).
      final delay = Duration(seconds: _fails >= 5 ? 30 : _fails);
      await Future.delayed(delay);
      if (mounted) {
        setState(() => _error = 'PIN errato ($_fails tentativi)');
        _pinCtrl.clear();
      }
    } finally {
      if (mounted) setState(() => _waiting = false);
    }
  }

  /// PIN-wrapped device key: the PIN unwraps it cryptographically and the
  /// vault opens directly — a wrong PIN simply fails AEAD, so no PIN value
  /// or hash is ever stored anywhere.
  Future<bool> _unlockPinFirst(String pin) async {
    try {
      await store.unlockWithPin(pin);
      plat.onVaultChanged(() => store.reloadFromStorage());
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final hello = store.lockMode == 'hello';
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 340),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(hello ? Icons.fingerprint : Icons.pin_outlined, size: 56),
              const SizedBox(height: 16),
              Text('AlienMsg',
                  style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 24),
              if (hello) ...[
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: _helloRunning ? null : _helloAuth,
                    icon: const Icon(Icons.fingerprint),
                    label: Text(_helloRunning
                        ? 'Verifica in corso…'
                        : 'Sblocca con Windows Hello'),
                  ),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(_error!,
                      style:
                          TextStyle(color: Theme.of(context).colorScheme.error)),
                ],
              ] else ...[
                TextField(
                  controller: _pinCtrl,
                  obscureText: true,
                  autofocus: true,
                  enabled: !_waiting,
                  keyboardType: TextInputType.number,
                  textAlign: TextAlign.center,
                  decoration: InputDecoration(
                    labelText: 'PIN',
                    border: const OutlineInputBorder(),
                    errorText: _error,
                  ),
                  onSubmitted: (_) => _waiting ? null : _tryPin(),
                ),
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: _waiting ? null : _tryPin,
                    icon: const Icon(Icons.lock_open),
                    label: const Text('Sblocca'),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _pinCtrl.dispose();
    super.dispose();
  }
}

/// Copy helper used across screens. Web/Safari can deny programmatic
/// clipboard writes — report honestly instead of lying "copied".
Future<void> copyToClipboard(BuildContext context, String text,
    [String? label]) async {
  String msg = label ?? 'Copiato negli appunti';
  try {
    await Clipboard.setData(ClipboardData(text: text));
  } catch (_) {
    msg = 'Copia automatica non riuscita — seleziona il testo a mano';
  }
  if (context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }
}
