// 设置 › 隐私与分享 › 改进 DSH Go: the switch for anonymous usage statistics
// (lib/usage/usage_stats.dart) and, under it, what goes out.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/l10n.dart';
import '../../usage/usage_stats.dart';
import '../../services/site_service.dart';
import 'settings_widgets.dart';

class UsageStatsSection extends ConsumerStatefulWidget {
  const UsageStatsSection({super.key});

  @override
  ConsumerState<UsageStatsSection> createState() => _UsageStatsSectionState();
}

class _UsageStatsSectionState extends ConsumerState<UsageStatsSection> {
  @override
  void initState() {
    super.initState();
    // The switch and its sentence on screen count as being told.
    unawaited(ref.read(usageStatsProvider.notifier).markNoticed());
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final enabled = ref.watch(usageStatsProvider.select((s) => s.enabled));
    final status = ref.watch(siteServiceStatusProvider);
    final available = status.asData?.value.usage ?? false;
    return SettingsSection(
      title: l10n.usageStatsSection,
      footer: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(l10n.usageStatsFooter),
          if (!available) ...[
            Text(l10n.siteServiceUnavailable),
            TextButton(onPressed: () => ref.invalidate(siteServiceStatusProvider), child: Text(l10n.siteServiceRetry)),
          ],
        ],
      ),
      children: [
        SettingsSwitchTile(
          spot: Spots.usageStats,
          value: enabled,
          onChanged: available || enabled
              ? (on) => unawaited(ref.read(usageStatsProvider.notifier).setEnabled(on))
              : null,
        ),
      ],
    );
  }
}
