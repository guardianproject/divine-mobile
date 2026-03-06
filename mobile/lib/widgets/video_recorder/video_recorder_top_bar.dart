// ABOUTME: Top bar widget for video recorder screen
// ABOUTME: Contains close button, segment-bar, and forward button

import 'package:divine_ui/divine_ui.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:openvine/providers/clip_manager_provider.dart';
import 'package:openvine/providers/video_recorder_provider.dart';
import 'package:openvine/utils/unified_logger.dart';
import 'package:openvine/widgets/video_editor/audio_editor/video_editor_audio_chip.dart';

/// Top bar with close button, segment bar, and forward button.
class VideoRecorderTopBar extends ConsumerWidget {
  /// Creates a video recorder top bar widget.
  const VideoRecorderTopBar({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final notifier = ref.read(videoRecorderProvider.notifier);
    final recorderState = ref.watch(videoRecorderProvider);
    final clipCount = ref.watch(clipManagerProvider.select((s) => s.clipCount));
    final hasClips = clipCount > 0;
    final isRecording = recorderState.isRecording;
    final selectedSound = recorderState.selectedSound;

    // Debug logging for Next button visibility
    Log.debug(
      '🔝 TopBar build: hasClips=$hasClips, clipCount=$clipCount, '
      'isRecording=$isRecording',
      name: 'VideoRecorderTopBar',
      category: LogCategory.video,
    );

    return Align(
      alignment: .topCenter,
      child: SafeArea(
        child: AnimatedSwitcher(
          duration: const Duration(milliseconds: 200),
          child: isRecording
              ? const SizedBox.shrink()
              : Padding(
                  padding: const .fromLTRB(16, 40, 16, 0),
                  child: Row(
                    spacing: 16,
                    mainAxisAlignment: .spaceBetween,
                    children: [
                      // Close button
                      DivineIconButton(
                        // TODO(l10n): Replace with context.l10n when localization is added.
                        semanticLabel: 'Close video recorder',
                        type: .ghostSecondary,
                        size: .small,
                        icon: .x,
                        onPressed: () => notifier.closeVideoRecorder(context),
                      ),

                      Flexible(
                        child: VideoEditorAudioChip(
                          selectedSound: selectedSound,
                          onSoundChanged: notifier.selectSound,
                          onSelectionStarted: notifier.pauseRemoteRecordControl,
                          onSelectionEnded: notifier.resumeRemoteRecordControl,
                        ),
                      ),

                      // Next button
                      Opacity(
                        opacity: hasClips ? 1 : 0.32,
                        child: DivineIconButton(
                          // TODO(l10n): Replace with context.l10n when localization is added.
                          semanticLabel: 'Continue to video editor',
                          type: .tertiary,
                          size: .small,
                          icon: .check,
                          onPressed: hasClips
                              ? () => notifier.openVideoEditor(context)
                              : null,
                        ),
                      ),
                    ],
                  ),
                ),
        ),
      ),
    );
  }
}
