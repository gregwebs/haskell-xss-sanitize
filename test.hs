import Text.HTML.SanitizeXSS

main = do
  let test = " <a href='unsafe://hack.com'>anchor</a> <img src='evil://evil.com' /> <unsafe></foo> <bar /> <br></br> "
  let actual = (sanitizeXSS test)
  let expected = " <a>anchor</a> <img />   <br /> "
  putStrLn $ if actual == expected then "pass" else "failure parsing:" ++ (show test) ++ "\nexpected:" ++ (show expected) ++ "\nactual:  " ++ (show actual)
