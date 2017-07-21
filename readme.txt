=== WP-Venus ===
Contributors: mortenf
Donate link: http://www.mfd-consult.dk/paypal/
Tags: integration, syndication, feeds, rss, atom
Requires at least: 2.0.4
Tested up to: 2.3.2
Stable tag: trunk

A plugin for running a syndication planet using Planet Venus through its cache directory, with complete support for multi author feeds and categories.

== Description ==

This plugin monitors a [Planet Venus](http://www.intertwingly.net/code/venus/ "Planet Venus") cache
directory and syndicates new entries as posts.
It automagically creates users and categories as necessary.

The plugin was originally released on [Binary Relations](http://www.wasab.dk/morten/blog/archives/2006/10/22/wp-venus "WP: Venus") by [Morten Frederiksen](http://www.wasab.dk/morten/).

== Installation ==

1. Install the WordPress Venus plugin as any other plugin into the wp-content/plugins directory.
1. Activate the plugin from the WordPress plugin administration screen.
1. Go to the Venus option screen and configure:
   * Absolute path to the Venus cache directory:
     This must contain the complete location of the Venus Atom entry files on the local server that WordPress is running on. The directory may contain subdirectories, but they will not be examined.
   * Default role for new users:
     Change this if you want users created by the plugin to have a different role (the default is "Author").
   * Minimum update interval (minutes):
     This interval should be set to a little lower than the interval at which Venus itself is run. If you run Venus every hour, try setting this to 55 minutes.
   * Tag with source URL?:
     Check this if you want the plugin to assign a tag with the URL of the source to each new post.
   * Check entry size?:
     Check this if you want the plugin to not only check the modification time of entries in the cache directory, but also see if the size of each entry file has changed.
   * Use original link to post?:
     Check this if you want permalinks on index pages and in feeds to point at the remote site where the post originated from.
1. Set up a cron job to fetch http://yoursite.example.com/wp-content/plugins/wp-venus.php every hour or so (at least the interval you configured above). You probably want to schedule this the same way you schedule Venus itself. If you are unable to schedule cron jobs, you may instead uncomment the very last line of the plugin (the one with 'wp_head' and 'update'). That will make the plugin look for posts on page loads, but only as often as specified in the update interval configuration. This is not the recommend method, as it slows down page loads for (some) visitors.
1. Sit back and relax...

== Screenshots ==

1. Venus options

2. Merging users

== Maintenance ==

When running correctly, the WordPress Venus plugin automatically adds users, categories and posts as needed, based on the information in the Atom entry files from the Venus cache directory. Each Atom entry file is only parsed when created or updated, so you may update existing posts, categories and users in WordPress as needed, in case something looks odd -- your changes will not be overwritten unless the entry file is updated. If you delete a post, the plugin will try to remove the corresponding Atom entry file in the cache directory as well. For that to work, the web server process needs write permission to the cache directory.

If you find that the same users suddenly appears more than once in the WordPress user system (this may happen if the same user posts from different sources), you can use the Venus options screen to merge the two into one. The merge will be preserved for future arriving posts. This is accomplished by storing unique IDs for each user, as can be seen and maintained on the user edit screen.

Since the plugin scans the Venus cache directory to look for updates, you will likely find, that it slows down after a while. You may want to clean out the cache directory every now and then, possibly through the use of a cron job, and Venus's -x switch.

== Frequently Asked Questions ==

= Do I really need cron to use this plugin? =

No.

If you are unable to schedule cron jobs, you may instead uncomment the very last line of the plugin (the one with 'wp_head' and 'update'). That will make the plugin look for posts on page loads, but only as often as specified in the update interval configuration. This is not the recommend method, as it slows down page loads for (some) visitors. Also, you likely need cron to run Venus itself anyway...

== Change Log ==

From 1.1 to 1.2:
----------------
* Fixed file includes for WordPress MU.

From 1.0 to 1.1:
----------------
* Added option for tagging with source URL.
* Added button for immediate update from cache.
* Added user consolidation mantainance.
* Added selectable default user role.
* Improved compatibility with WordPress MU.
* Fixed problem with Gengo-compatibility.
* Fixed category parsing.

From 0.6 to 1.0:
----------------
* Released on http://svn.wp-plugins.org/wp-venus/

From 0.5 to 0.6:
----------------
* Added flag for optional checking of entry file size for detecting updates
* Added debug log
* Fixed GUID generation

From 0.4 to 0.5:
----------------
* On post delete now also removes cache file, if possible

From 0.3 to 0.4:
----------------
* To improve response time, a separate GET of the plugin is now needed
* Better category handling
* Improved user consolidation
* Permalinks also supported for guid
* Fixed bug regarding using atom:id as permalink

From 0.2 to 0.3:
----------------
* Added complete feed support
* Fixed invalid permalinks

From 0.1 to 0.2:
----------------
* Improved handling of missing categories and excerpts
* Better author identification and creation
* Fixed permalink generation
* Added user consolidation routine

== License ==

Copyright (c) 2006-2007 Morten Frederiksen <morten@wasab.dk>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
