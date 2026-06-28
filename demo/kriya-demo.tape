# kriya control-plane pilot — recorded demo (VHS). Renders GIF + MP4 of demo/story-demo.sh
# running over the REAL binaries. Reproduce:  vhs demo/kriya-demo.tape   (run from repo root)
Output demo/kriya-pilot-demo.gif
Output demo/kriya-pilot-demo.mp4

Require bash

Set Shell "bash"
Set FontSize 15
Set Width 1240
Set Height 780
Set Padding 26
Set Framerate 12
Set TypingSpeed 14ms

Type "bash demo/story-demo.sh"
Sleep 500ms
Enter
Sleep 64s
