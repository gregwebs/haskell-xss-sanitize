import Text.HTML.SanitizeXSS

testHTML = " <a href='http://safe.com'>safe</a><a href='unsafe://hack.com'>anchor</a> <img src='evil://evil.com' /> <unsafe></foo> <bar /> <br></br> <b>Unbalanced</div><img src='http://safe.com'>"

test actual expected = do
  putStrLn $ "testing: " ++ testHTML
  putStrLn $ if actual == expected then "pass" else "failure\n" ++ "\nexpected:" ++ (show expected) ++ "\nactual:  " ++ (show actual)

main = do
  test (sanitizeBalance testHTML) " <a href=\"http://safe.com\">safe</a><a>anchor</a> <img />   <br /> <b>Unbalanced<div></div><img src=\"http://safe.com\"></b>"
  test (sanitizeXSS testHTML) " <a href=\"http://safe.com\">safe</a><a>anchor</a> <img />   <br /> <b>Unbalanced</div><img src=\"http://safe.com\">"
