Summary
=======
provides 2 functions in the module Text.HTML.SanitizeXSS

* sanitize - filters html to prevent XSS attacks.
* sanitizeBalance - same as sanitize but makes sure there are no lone opening/closing tags - useful to protect against a user's html messing up your page

Use Case
========
HTML from an untrusted source (user of a web application) should be ran through this library.
If you trust the HTML (you wrote it), you do not need to use this.
If you don't trust the html you probably also do not trust that the tags are balanced and should use sanitizeWithBalancing.

Detail
========
This is not escaping! Escaping html does prevent XSS attacks. Strings (that aren't meant to be HTML) should be HTML escaped to show up properly and to prevent XSS attacks. However, escaping will ruin the display of actual HTML.

This function removes any HTML tags or attributes that are not in its white-list. This may sound picky, but most HTML should make it through unchanged, making the process unnoticeable to the user but giving us safe HTML. 

Integration
===========
It is recommended to integrate this so that it is automatically used whenever an application receives untrusted html data (instead of before it is displayed). See the Yesod web framework as an example.

Credit
===========
Original code was taken from John MacFarlane's Pandoc (with permission), but modified to be faster and with parsing redone using TagSoup. html5lib is now being used as a reference (BSD style license).
Michael Snoyman added the balanced tags functionality and released css-text specifically to help with css parsing.


Limitations
===========

Lowercase
---------
All tag names and attribute names are converted to lower case as a matter of convenience. If you have a use case where this is undesirable let me know.

Balancing - sanitizeBalance
---------------------------------
The goal of this function is to prevent your html from breaking when (unknown) html with unbalanced tags are placed inside it. I would expect it to work very well in practice and don't see a downside to using it unless you have an alternative approach. However, this function does not at all guarantee valid html. In fact, it is likely that the result of balancing will still be invalid HTML. There is no guarantee for how a browser will display invalid HTML, so there is no guarantee that this function will protect your HTML from being broken by a user's html. Other possible approaches would be to run the HTML through a library like libxml2 which understands HTML or to first render the HTML in a hidden iframe or hidden div at the bottom of the page so that it is isolated, and then use JavaScript to insert it into the page where you want it.

TagSoup Parser
--------------
TagSoup is used to parse the HTML, and it does a good job. However TagSoup does not maintain all white space. TagSoup does not distinguish between the following cases:

    <a href="foo">, <a href=foo>
    <a   href>, <a href>
    <a></a>, <a/>

In the third case, img and br tags will be output as a single self-closing tags. Other self-closing tags will be output as an open and closing pair. So `<img /> or <img><img>` converts to `<img />`, and `<a></a> or <a/>` converts to `<a></a>`.  There are future updates to TagSoup planned so that TagSoup will be able to render tags exactly the same as they were parsed.

Where is the white list from?
-----------------------------
Ultimately this is where your security comes from. I would expect that a basic, incomplete white list would act as a strong deterrent, but this library strives for completeness.

The [source code of html5lib](http://code.google.com/p/html5lib/source/browse/python/html5lib/sanitizer.py) is the source of the white list and my implementation reference. They reference [a wiki page containing a white list](http://wiki.whatwg.org/wiki/Sanitization_rules), and hopefully they are careful of when they import into their code. Working with the maintainers of html5lib may make sense, but it doesn't make sense to merge the projects because sanitization is just one aspect of html5lib (They have a parser also).

If anyone knows of better sources or thinks a particular tag/attribute/value may be vulnerable, please let me know.
[HTML Purifier](http://htmlpurifier.org/live/smoketests/printDefinition.php) does have a more permissive and configurable (yet safe) white list if you are looking to add anything.

style attribute
----------------
style attributes are now parsed with the css-text and autoparsec-text dependencies. They are then ran through a white list for properties and keywords. Whitespace is not preserved. This code was again translated from sanitizer.py, but uses attopoarsec-text instead of regexes. If you don't care about stripping css you can avoid an attoparsec-text dependending on the older < 0.3 version of this library.

data attributes
-------------------------
data attributes are not on the white list.
The href attribute is white listed, but its value must pass through a white list also. This is how the data attributes could work also.

svg and mathml
--------------
A mathml white list is fully implemented. There is some support for svg styling. 
There is a full white list for svg elements and attributes. However, some elements are not included because they need further filtering (just like the data attributes) and this has not been done yet.
