Summary
=======
provides a function Text.HTML.SanitizeXSS.sanitizeXSS that filters html to prevent XSS attacks.

Use Case
========
All html from an untrusted source (user of a web application) should be ran through this function.
If you trust the html (you wrote it), you do not need to use this.

Detail
========
This is not escaping! Escaping html does prevents XSS attacks. Strings should be html escaped to show up properly and to prevent XSS attacks. However, escaping will ruin the display of the html.

This function removes any tags or attributes that are not in its white-list of. This may sound picky, but most html should make it through unchanged, making the proces unnoticeable to the user but giving us safe html. 

Limitations
-----------
TagSoup is used to parse the HTML, and it does a good job. However TagSoup does not maintain all white space. TagSoup does not distinguish between the following cases:

    <a href="foo">, <a href=foo>
    <a   href>, <a href>
    <a></a>, <a/>

In the third case, img and br tags will be output as a single self-closing tags. Other self-closing tags will be output as an open and closing pair. So `<img /> or <img><img>` converts to `<img />`, and `<a></a> or <a/>` converts to `<a></a>`.  There are future updates to TagSoup planned so that TagSoup will be able to render tags exactly the same as they were parsed.

Integration
===========
It is recommended to integrate this so that it is automatically used whenever an application receives untrusted html data (instead of before it is displayed). See the Yesod web framework as an example.

Credit
===========
This was taken from John MacFarlane's Pandoc (with permission) modified to be faster and parsing redone with TagSoup
