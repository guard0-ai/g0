# g0 README demo — regenerate from repo root:
#   npm run build && vhs assets/demo.tape
# Records against a sandboxed HOME (see assets/demo-setup.sh); no real
# machine configs or secrets appear in the output.

Output assets/demo.gif

Set Shell bash
Set FontSize 15
Set Width 1200
Set Height 750
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "source assets/demo-setup.sh && clear"
Enter
Sleep 1s
Show

Type "g0 endpoint"
Sleep 500ms
Enter
Sleep 7s

Type "clear"
Enter
Sleep 300ms

Type "g0 scan ./my-agent"
Sleep 500ms
Enter
Sleep 10s
