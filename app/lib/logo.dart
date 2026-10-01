import 'dart:math' as math;

import 'package:flutter/material.dart';

/// The AlienMsg logo, drawn on a [Canvas]: an alien head with glowing eyes
/// and a thin orbital ring (messages travelling between worlds). Used by the
/// app icon, the splash screen and about dialogs.
class AlienLogo extends StatelessWidget {
  const AlienLogo({super.key, this.size = 96, this.showBackground = true});

  final double size;

  /// Rounded dark tile behind the mark (app icon look). False for transparent.
  final bool showBackground;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
          painter: AlienLogoPainter(showBackground: showBackground)),
    );
  }
}

class AlienLogoPainter extends CustomPainter {
  const AlienLogoPainter({this.showBackground = true});

  final bool showBackground;

  static const _deep = Color(0xFF1A1030);
  static const _violet = Color(0xFF7C4DFF);
  static const _lilac = Color(0xFFB49CFF);
  static const _glow = Color(0xFFCFBBFF);

  @override
  void paint(Canvas canvas, Size size) {
    final s = size.width;
    canvas.save();
    canvas.scale(s / 100, s / 100); // 100x100 logical space

    if (showBackground) {
      final r = RRect.fromRectAndRadius(
          const Rect.fromLTWH(0, 0, 100, 100), const Radius.circular(22));
      final bg = Paint()
        ..shader = const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF241643), _deep],
        ).createShader(const Rect.fromLTWH(0, 0, 100, 100));
      canvas.drawRRect(r, bg);
      canvas.clipRRect(r);
    }

    // Orbital ring (behind the head where it passes at the back).
    final ringRect = Rect.fromCenter(
        center: const Offset(50, 52), width: 92, height: 34);
    final ringPath = Path()..addOval(ringRect);
    final ringPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.4
      ..color = _violet.withValues(alpha: 0.85);
    // Tilt the ring so it reads as an orbit.
    canvas.save();
    canvas.translate(50, 52);
    canvas.rotate(-0.35);
    canvas.translate(-50, -52);
    canvas.drawPath(_ringBackHalf(ringPath, ringRect), ringPaint);
    canvas.restore();

    // Alien head: wide cranium tapering to a soft chin.
    final head = Path()
      ..moveTo(50, 18)
      ..cubicTo(74, 18, 84, 38, 82, 52)
      ..cubicTo(80, 66, 66, 84, 50, 86)
      ..cubicTo(34, 84, 20, 66, 18, 52)
      ..cubicTo(16, 38, 26, 18, 50, 18);
    final headPaint = Paint()
      ..shader = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [_lilac, _violet],
      ).createShader(const Rect.fromLTWH(16, 16, 68, 72));
    canvas.drawPath(head, headPaint);

    // Almond eyes — dark voids with a violet glow.
    for (final side in [-1, 1]) {
      final cx = 50 + side * 17.0;
      final eye = Path()
        ..moveTo(cx - 11, 52)
        ..quadraticBezierTo(cx, 42, cx + 11, 50)
        ..quadraticBezierTo(cx + 2, 60, cx - 11, 52);
      canvas.drawPath(eye, Paint()..color = _deep);
      // Inner glow dot
      canvas.drawCircle(
          Offset(cx + side * -2.5, 50.5), 2.6, Paint()..color = _glow);
    }

    // Ring front half — drawn over the head's lower area.
    canvas.save();
    canvas.translate(50, 52);
    canvas.rotate(-0.35);
    canvas.translate(-50, -52);
    canvas.drawPath(_ringFrontHalf(ringPath, ringRect), ringPaint);
    canvas.restore();

    // Tiny satellite dot on the ring.
    canvas.drawCircle(
        const Offset(87, 40), 2.2, Paint()..color = _glow);

    canvas.restore();
  }

  Path _ringBackHalf(Path ringPath, Rect rect) {
    // Upper half of the ellipse (behind the head).
    return Path()
      ..addArc(rect, math.pi + 0.15, math.pi - 0.3);
  }

  Path _ringFrontHalf(Path ringPath, Rect rect) {
    // Lower half of the ellipse (in front of the chin).
    return Path()
      ..addArc(rect, 0.15, math.pi - 0.3);
  }

  @override
  bool shouldRepaint(AlienLogoPainter old) =>
      old.showBackground != showBackground;
}
