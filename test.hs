import Text.HTML.SanitizeXSS

main = do
  let test = " <a href='unsafe://hack.com'>anchor</a> <img src='evil://evil.com' /> </foo> "
  let result = (sanitizeXSS test)
  let expected = " <a>anchor</a> <img />  "
  putStrLn $ if result == expected then "pass" else "failure parsing:" ++ (show test) ++ "\nexpected:" ++ (show expected) ++ "\nactual:  " ++ (show result)
