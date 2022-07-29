# Steins;Gate Textractor
Only works for Steins;Gate and Steins;Gate 0. This is a proof of concept,
can easily be adapted to copy to clipboard for standard texthooker such 
as ITHVNR or NextHooker. Character mapping was provided by 
[CommitteeOfZero](https://github.com/CommitteeOfZero/SciAdv.Net/blob/master/src/SciAdvNet.SC3/Data/SteinsGateZero/Charset.utf8),
all other work was done by me. I believe this works for all versions of
Steins;Gate and 0, no guarantees though. Steam version seems to have a different character mapping. This version was generated through OCR, as well as [Geniussmit](https://github.com/Geniusssmit) carefully sifting through the results for errors.
> Note: Neither menus nor popups are handled, and not all text on the 
cell phone is handled, such as names on the contacts screen.
### Build Instructions
Made with VS2017, requires any windows SDK, otherwise should compile 
out-of-the-box.
### Use Instructions
Running this program should be all you need to do, make sure that 
mages_charset.bin is in the same directory as the executable.
It will print any new text bubbles to console, and will print e-mail
sender, subject, and body upon opening said e-mail. For s;g0 it prints
the full conversation to console. If you are playing the Japanese version from Steam and the text being output isn't correct, swap mages_charset.bin for mages_charset_steam.bin (make sure that mages_charset_steam.bin is renamed to mages_charset.bin). To play Linear Bounded Phenogram or Darling's Embrace, rename the respective charset to mages_charset.bin.
> Make sure to close and reopen after closing the game, as it doesn't reopen on its own.
### Sample Images
It's self-explanatory.
![sample1](https://shiiion.me/i/s7k61.png)![sample2](https://shiiion.me/i/vy1mx.png)
