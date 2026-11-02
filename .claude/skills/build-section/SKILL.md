---
name: build-section
description: How to build or change pages and sections of the CV Hair Emporium site (Flask, Jinja templates, Bootstrap 5, plain CSS). Use whenever adding a page, a section, a component, or changing the booking flow.
---

# Building pages and sections

Always follow the brand-style skill for how things look. This skill covers how things are built.

## Stack — keep it
- Flask app with Jinja templates. Static files live in `static/css`, `static/js`, `static/images`.
- Bootstrap 5.3 for the grid, utilities and the collapsing nav. Custom styling goes in the CSS files, not inline `style=""`.
- Do not add React, Tailwind, Next.js or another CSS framework. Do not add a JavaScript library when a few lines in `static/js/scripts.js` will do.
- Load Bootstrap once, from one version. The site currently loads Bootstrap 5.3.0 and 5.3.2 (CSS and JS) at the same time; when touching the base template, remove the duplicate.

## Before writing code
1. Read the base template that other pages extend and reuse its blocks. Never copy the nav or footer into a new page.
2. Check whether a similar section already exists and reuse its classes.
3. Say in one or two lines what you will change and in which files.

## Templates
- Every page extends the base template. Page-specific CSS goes in that page's own file (for example `home.css`) and is loaded only by that page, through a block in the base template — not linked on every page.
- Use semantic HTML: one `<h1>` per page, sections in `<section>` with a heading, buttons that navigate are `<a>`, buttons that act are `<button>`.
- Images: real photos of the stylist's work, with descriptive `alt` text, `loading="lazy"` below the first screen, and explicit width and height to prevent layout jumps.

## Booking
- Booking goes through the Cal.com link. Keep that URL in one place (a Flask config value passed to templates), never pasted into several templates.
- Every page shows a visible Book Now button within the first screen on a phone.
- Service-specific booking links, if added, must point to the matching Cal.com event, never to a generic page.

## Services and prices
- Keep the service list in one data source (a Python list or JSON file) and render it with a Jinja loop. Do not hand-write each service in HTML.
- Each service has: category, name, optional length or variant, price, and whether the price is "from" (shown with "+").
- When editing prices, check that variants make sense against each other (for example, "hair provided" should not cost less than "hair not provided" unless the stylist confirms it).

## Phone first
- Write the phone layout first, then add `md`/`lg` changes. The nav collapses under 1024px (Bootstrap `lg`). The hero uses a still image under 766px and the carousel above that.
- Tap targets at least 44px tall. No horizontal scrolling at 375px wide.

## Forms and accounts
- Login, register, reviews and password reset use Flask forms with CSRF protection and server-side validation. Show errors next to the field that caused them.
- Never put secrets, API keys or passwords in templates or static JavaScript.

## Finish every change by
1. Checking the page at 375px, 768px and 1280px wide.
2. Running the polish-review skill on what changed.
