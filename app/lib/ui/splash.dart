import 'package:flutter/material.dart';

import '../logo.dart';

/// Animated intro shown at every cold start while the vault boots.
/// The alien's eyes pulse and the ring sweeps; minimum ~1.1 s so it reads
/// as a deliberate intro, not a flicker.
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1400),
  )..repeat(reverse: true);

  late final Animation<double> _glow =
      CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut);

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: AnimatedBuilder(
          animation: _glow,
          builder: (_, __) => Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF7C4DFF)
                          .withValues(alpha: 0.25 + 0.35 * _glow.value),
                      blurRadius: 60 + 30 * _glow.value,
                      spreadRadius: 8,
                    ),
                  ],
                ),
                child: const AlienLogo(size: 140),
              ),
              const SizedBox(height: 28),
              Text('AlienMsg',
                  style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 8),
              Text(
                'Nessuno può leggere i tuoi messaggi',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 32),
              const SizedBox(
                  width: 22,
                  height: 22,
                  child: CircularProgressIndicator(strokeWidth: 2.4)),
            ],
          ),
        ),
      ),
    );
  }
}
