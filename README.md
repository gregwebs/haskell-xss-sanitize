Summary
=======
provides 2 functions in the module Text.HTML.SanitizeXSS
* sanitize - filters html to prevent XSS attacks.
* sanitizeBalance - same as sanitize but makes sure there are no lone closing tags - this could prevent a user's html from messing up your page

Use Case
========
HTML from an untrusted source (user of a web application) should be ran through this library.
If you trust the HTML (you wrote it), you do not need to use this.
If you don't trust the html you probably also do not trust that the tags are balanced- so you should use sanitizeWithBalancing.

Detail
========
This is not escaping! Escaping html does prevents XSS attacks. Strings should be html escaped to show up properly and to prevent XSS attacks. However, escaping will ruin the display of the html.

This function removes any tags or attributes that are not in its white-list. This may sound picky, but most html should make it through unchanged, making the process unnoticeable to the user but giving us safe html. 

Integration
===========
It is recommended to integrate this so that it is automatically used whenever an application receives untrusted html data (instead of before it is displayed). See the Yesod web framework as an example.

Credit
===========
Original code was taken from John MacFarlane's Pandoc (with permission), but modified to be faster and with parsing redone using TagSoup. html5lib is now being used as a reference (BSD style license).
Michael Snoyman added the balanced tags functionality.


Limitations
===========

Balancing - sanitizeBalance
---------------------------------
The goal of this function is to prevent your html from breaking when unknown html is placed inside it. I would expect it to work very well in practice and don't see a downside to using it unless you have an alternative aproach. However, this function does not at all guarantee valid html. In fact, it is likely that the result of balancing will still be invalid HTML. This means there is still no guarantee what a browser will do with the html, so there is no guarantee that it will prevent you html from breaking. Other possible aproaches would be to run the html through a library like libxml2 which understands html or to first render the html in a hidden iframe or maybe a hidden div at the bottom of the page so that it is isolated, and then use javascript to insert it into the page where you want it.

TagSoup Parser
--------------
TagSoup is used to parse the HTML, and it does a good job. However TagSoup does not maintain all white space. TagSoup does not distinguish between the following cases:

    <a href="foo">, <a href=foo>
    <a   href>, <a href>
    <a></a>, <a/>

In the third case, img and br tags will be output as a single self-closing tags. Other self-closing tags will be output as an open and closing pair. So `<img /> or <img><img>` converts to `<img />`, and `<a></a> or <a/>` converts to `<a></a>`.  There are future updates to TagSoup planned so that TagSoup will be able to render tags exactly the same as they were parsed.

Where is the white list from?
-----------------------------
Ultimately this is where your security comes from, although I would tend to think that even a basic, incomplete white list would act as a strong deterrent.

Version 0.1 of the white list is from Pandoc which is generally stricter than it needs to be but possibly allows unsafe protocols in links.

Version >= 0.2 uses (the source code of html5lib)[http://code.google.com/p/html5lib/source/browse/python/html5lib/sanitizer.py]. as the source of the white list and my implementation reference. They reference (a wiki page containing a white list)[http://wiki.whatwg.org/wiki/Sanitization_rules], and hopefully they are careful of when they import into their code. Working with the maintainers of html5lib may make sense, but it doesn't make sense to merge the projects because sanitization is just one aspect of html5lib (They have a parser also).

If anyone knows of better sources or thinks a particular tag/attribute/value may be vulnerable, please let me know.

attributes data and style
-------------------------
The href attribute is white listed, but its value must pass through a white list also. This is how the data and style attributes should work also. However, this was never implemented in Pandoc, and the html5lib code is a little complicated and relies on regular expressions that I don't understand. So for now these attributes are not on the white list.

svg and mathml
--------------
A mathml white list is fully implemented.
There is a white list for svg elements and attributes. However, some elements are not included because they need further filtering (just like the data and style html attributes)
