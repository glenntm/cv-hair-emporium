---
name: polish-review
description: Final quality check for CV Hair Emporium pages before they go live. Use when the user types /polish-review, asks to review, polish or check a page, or after finishing a section.
disable-model-invocation: true
---

# Polish review

Review the page or section the user names (or the one just changed). Report findings as a short list grouped by **Must fix**, **Should fix**, and **Nice to have**, each with the file and a one-line fix. Then ask before changing anything beyond the obvious must-fixes.

## 1. Brand (check against the brand-style skill)
- Violet #9400FF is the only accent. No gold, blue or new colors in the live look; lilac #9694FF only on the stats strip.
- Archivo everywhere; headings weight 900; small labels uppercase, weight 700, 0.1em letter-spacing, violet.
- Flat surfaces: no 12px rounded cards, no soft drop shadows. Buttons have 4px corners and fill to #1A1A1A from the left on hover.
- Section padding 60–100px vertical; content max width 80rem; body text under ~40rem wide.

## 2. Readability and contrast
- Text on photos must stay readable: add a dark overlay behind hero text if needed. Violet labels over photography are the usual failure — check them on the phone hero.
- Body text and buttons meet WCAG AA contrast (4.5:1 for body text).

## 3. Phone first
- Check at 375px, 768px and 1280px. No horizontal scroll, nothing cut off, tap targets at least 44px.
- Nav collapses under 1024px and the menu opens and closes. Hero shows the still image under 766px and the carousel above.
- The Book Now button is visible on the first screen of every page on a phone.

## 4. Booking path
- Every Book Now and booking link opens the correct Cal.com page.
- Phone (`tel:`), email (`mailto:`), address (maps) and Instagram links are real and correct.

## 5. Content
- No placeholder or test content: search for `example.com`, "test", "lorem", sample reviews and dummy names.
- Spelling of every service name and label (watch for "weak" vs "weave", "individial", "comb out").
- Prices: consistent "$ + " format, "From $X+" only on category headers, and variants that make sense against each other.
- Stats (years, customers, appointments, satisfaction) are real numbers the stylist has confirmed.

## 6. Technical
- No console errors. Bootstrap loaded once, one version.
- Each page loads only its own CSS file plus the shared ones.
- Images compressed (ideally under 300KB each), with alt text, lazy-loaded below the first screen.
- Each page has a unique `<title>` and meta description mentioning the salon and Chicago.
