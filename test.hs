import Text.HTML.SanitizeXSS

main = do
  let test = " <a href='http://safe.com'>safe</a><a href='unsafe://hack.com'>anchor</a> <img src='evil://evil.com' /> <unsafe></foo> <bar /> <br></br> "
  let actual = (sanitizeXSS test)
  let expected = " <a href=\"http://safe.com\">safe</a><a>anchor</a> <img />   <br /> "
  putStrLn $ "testing: " ++ test
  putStrLn $ if actual == expected then "pass" else "failure\n" ++ "\nexpected:" ++ (show expected) ++ "\nactual:  " ++ (show actual)
