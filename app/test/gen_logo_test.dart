import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:alienmsg/logo.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Future<Uint8List> renderLogo(int px, {required bool background}) async {
  final recorder = ui.PictureRecorder();
  final canvas = Canvas(recorder);
  const AlienLogoPainter(showBackground: true)
      .paint(canvas, const Size.square(1024));
  final pic = recorder.endRecording();
  final img = await pic.toImage(px, px);
  final data = await img.toByteData(format: ui.ImageByteFormat.png);
  return data!.buffer.asUint8List();
}

void main() {
  test('generate logo PNGs', () async {
    // Full icon (with dark tile)
    {
      final recorder = ui.PictureRecorder();
      final canvas = Canvas(recorder);
      const AlienLogoPainter(showBackground: true)
          .paint(canvas, const Size(1024, 1024));
      final img = await recorder.endRecording().toImage(1024, 1024);
      final data = await img.toByteData(format: ui.ImageByteFormat.png);
      File('assets/icon/logo.png')
          .writeAsBytesSync(data!.buffer.asUint8List());
    }
    // Foreground (transparent) for adaptive icons — slightly zoomed-out mark
    {
      final recorder = ui.PictureRecorder();
      final canvas = Canvas(recorder);
      canvas.translate(1024 * 0.18, 1024 * 0.18);
      const AlienLogoPainter(showBackground: false)
          .paint(canvas, const Size(1024 * 0.64, 1024 * 0.64));
      final img = await recorder.endRecording().toImage(1024, 1024);
      final data = await img.toByteData(format: ui.ImageByteFormat.png);
      File('assets/icon/logo_fg.png')
          .writeAsBytesSync(data!.buffer.asUint8List());
    }
  });
}
