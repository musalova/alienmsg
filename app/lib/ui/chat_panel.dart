import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../store.dart';

/// A received item decoded from the transport pipeline.
/// [from] labels the sender on group messages; [system] renders as a centered
/// notice instead of a chat bubble.
class ReceivedMsg {
  final String? from;
  final String text;
  final bool system;
  const ReceivedMsg(this.text, {this.from, this.system = false});
}

// Pseudo-word transport: every "word" is exactly one syllable
// (consonant + vowel or vowel-cluster). Real sentences almost never match.
final _wordsRe = RegExp(
    r'^[bdfghjklmnprstvz](ai|au|ei|ia|ie|io|oa|oi|ua|ue|ui|[aeiou])'
    r'([. ]+[bdfghjklmnprstvz](ai|au|ei|ia|ie|io|oa|oi|ua|ue|ui|[aeiou]))*[. ]*$');

/// True when [t] looks like an AlienMsg transport code (blob, emoji or
/// pseudo-words). Used for clipboard auto-detection.
bool looksLikeCode(String t) {
  final s = t.trim();
  return s.startsWith('AYA1:') ||
      s.contains('👽') ||
      (s.length > 100 && _wordsRe.hasMatch(s));
}

/// Chat-style panel for non-technical users: one field to write, one button
/// to send (the encrypted code is copied automatically), one button to read
/// whatever the friend pasted into the clipboard.
///
/// When [historyKey] is given, messages are persisted in the encrypted vault
/// so the conversation survives app restarts.
class ChatPanel extends StatefulWidget {
  /// Encrypts [plaintext] and returns the rendered transport text.
  final String Function(String plaintext, String format) onSend;

  /// Decodes raw pasted text into a displayable message. Throws on failure.
  final ReceivedMsg Function(String raw) onReceive;

  /// Vault key for persistent history (see [Store.historyKeyForContact]).
  final String? historyKey;

  const ChatPanel(
      {super.key,
      required this.onSend,
      required this.onReceive,
      this.historyKey});

  @override
  State<ChatPanel> createState() => _ChatPanelState();
}

class _ChatPanelState extends State<ChatPanel> {
  final _ctrl = TextEditingController();
  final _scroll = ScrollController();
  final _msgs = <ChatEntry>[];
  String _format = 'blob';
  bool _codeInClipboard = false;

  /// Shared across instances: a code we just produced must not trigger the
  /// "codice copiato" banner when the user re-opens the chat.
  static String _lastCopied = '';

  static const _formats = {
    'blob': 'Codice (consigliato)',
    'emoji': 'Emoji',
    'words': 'Parole inventate',
  };

  @override
  void initState() {
    super.initState();
    final key = widget.historyKey;
    if (key != null) _msgs.addAll(store.history(key));
    _checkClipboard();
  }

  Future<void> _checkClipboard() async {
    try {
      final d = await Clipboard.getData(Clipboard.kTextPlain);
      final t = d?.text ?? '';
      if (mounted && looksLikeCode(t) && t.trim() != _lastCopied) {
        setState(() => _codeInClipboard = true);
      }
    } catch (_) {}
  }

  void _append(ChatEntry e) {
    setState(() => _msgs.add(e));
    final key = widget.historyKey;
    if (key != null) store.logMessage(key, e);
  }

  void _scrollDown() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  void _snack(String text) => ScaffoldMessenger.of(context)
      .showSnackBar(SnackBar(content: Text(text)));

  void _send() {
    final pt = _ctrl.text.trim();
    if (pt.isEmpty) return;
    final String code;
    try {
      code = widget.onSend(pt, _format);
    } catch (e) {
      _snack('Errore: $e');
      return;
    }
    Clipboard.setData(ClipboardData(text: code));
    _lastCopied = code;
    setState(() => _codeInClipboard = false);
    _append(ChatEntry(pt, mine: true));
    _ctrl.clear();
    _scrollDown();
    _snack('Copiato! Ora incollalo nella chat col tuo amico.');
  }

  String _friendlyError(Object e) {
    final s = e.toString();
    if (s.contains('replayed') || s.contains('duplicat')) {
      return 'Già letto — questo codice era già stato usato.';
    }
    if (s.contains('unknown') || s.contains('unsupported') ||
        s.contains('Malformed') || s.contains('Unknown')) {
      return 'Questo non sembra un codice AlienMsg.';
    }
    return 'Non riesco a leggerlo: $s';
  }

  Future<void> _readClipboard() async {
    // Web/Safari: getData can throw when the clipboard-read permission is
    // denied — surface it as a friendly message instead of an unhandled error.
    final String t;
    try {
      final d = await Clipboard.getData(Clipboard.kTextPlain);
      t = (d?.text ?? '').trim();
    } catch (_) {
      _snack('Non posso leggere gli appunti — autorizza l\'accesso o incolla a mano.');
      return;
    }
    if (t.isEmpty) {
      _snack(
          'Appunti vuoti — copia prima il codice che ti ha mandato il tuo amico.');
      return;
    }
    try {
      final r = widget.onReceive(t);
      _append(ChatEntry(r.text, from: r.from, system: r.system));
      setState(() => _codeInClipboard = false);
      _scrollDown();
    } catch (e) {
      _snack(_friendlyError(e));
    }
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _scroll.dispose();
    super.dispose();
  }

  Widget _bubble(BuildContext context, ChatEntry m) {
    final cs = Theme.of(context).colorScheme;
    if (m.system) {
      return Center(
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 6),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withValues(alpha: 0.6),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Text(m.text,
              style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant)),
        ),
      );
    }
    return Align(
      alignment: m.mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        constraints: const BoxConstraints(maxWidth: 420),
        decoration: BoxDecoration(
          color: m.mine ? cs.primaryContainer : cs.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (m.from != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 2),
                child: Text(m.from!,
                    style: TextStyle(
                        fontSize: 11,
                        color: cs.primary,
                        fontWeight: FontWeight.bold)),
              ),
            SelectableText(m.text),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        if (_codeInClipboard)
          MaterialBanner(
            content:
                const Text('Ho trovato un codice copiato. Lo leggo?'),
            leading: const Icon(Icons.move_to_inbox_outlined),
            actions: [
              TextButton(
                onPressed: () => setState(() => _codeInClipboard = false),
                child: const Text('Ignora'),
              ),
              FilledButton(
                onPressed: _readClipboard,
                child: const Text('Leggi'),
              ),
            ],
          ),
        Expanded(
          child: _msgs.isEmpty
              ? const Center(
                  child: Padding(
                    padding: EdgeInsets.all(32),
                    child: Text(
                      'Scrivi qui sotto e premi invio.\n'
                      'Il messaggio cifrato viene copiato da solo:\n'
                      'incollalo dove vuoi (SMS, chat, email).\n\n'
                      'Per leggere: copia il codice ricevuto e tocca 📥',
                      textAlign: TextAlign.center,
                    ),
                  ),
                )
              : ListView.builder(
                  controller: _scroll,
                  padding: const EdgeInsets.all(12),
                  itemCount: _msgs.length,
                  itemBuilder: (_, i) => _bubble(context, _msgs[i]),
                ),
        ),
        const Divider(height: 1),
        SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
            child: Row(
              children: [
                IconButton.filledTonal(
                  tooltip: 'Leggi codice dagli appunti',
                  onPressed: _readClipboard,
                  icon: const Icon(Icons.move_to_inbox_outlined),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    controller: _ctrl,
                    minLines: 1,
                    maxLines: 4,
                    textInputAction: TextInputAction.send,
                    onSubmitted: (_) => _send(),
                    decoration: const InputDecoration(
                      hintText: 'Scrivi un messaggio…',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                ),
                PopupMenuButton<String>(
                  tooltip: 'Formato del codice',
                  icon: const Icon(Icons.more_vert),
                  initialValue: _format,
                  onSelected: (f) => setState(() => _format = f),
                  itemBuilder: (_) => [
                    for (final e in _formats.entries)
                      PopupMenuItem(
                        value: e.key,
                        child: Row(children: [
                          Icon(
                              _format == e.key
                                  ? Icons.radio_button_checked
                                  : Icons.radio_button_off,
                              size: 18),
                          const SizedBox(width: 8),
                          Text(e.value),
                        ]),
                      ),
                  ],
                ),
                IconButton.filled(
                  tooltip: 'Invia (copia il codice)',
                  onPressed: _send,
                  icon: const Icon(Icons.send),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
