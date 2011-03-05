import Text.HTML.SanitizeXSS

testHTML = " <a href='http://safe.com'>safe</a><a href='unsafe://hack.com'>anchor</a> <img src='evil://evil.com' /> <unsafe></foo> <bar /> <br></br> <b>Unbalanced</div><img src='http://safe.com'>"

test f actual expected = do
  putStrLn $ "testing: " ++ actual
  putStrLn $ if f actual == expected then "pass" else "failure\n" ++ "\nexpected:" ++ (show expected) ++ "\nactual:  " ++ (show actual)

main = do
  test sanitizeBalance testHTML " <a href=\"http://safe.com\">safe</a><a>anchor</a> <img />   <br /> <b>Unbalanced<div></div><img src=\"http://safe.com\"></b>"
  test sanitize testHTML " <a href=\"http://safe.com\">safe</a><a>anchor</a> <img />   <br /> <b>Unbalanced</div><img src=\"http://safe.com\">"
  let testRelativeURI = "<a href=\"foo\">bar</a>"
  test sanitize testRelativeURI testRelativeURI
  let protocol_hack = "<script src=//ha.ckers.org/.j></script>"
  test sanitize protocol_hack ""
  let object_hack = "<object classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></object>"
  test sanitize object_hack ""
  let embed_hack = "<embed src=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></embed>"
  test sanitize embed_hack ""
  let ucase_image_hack = "<IMG src=javascript:alert('XSS') />"
  test sanitize ucase_image_hack "<img />"
