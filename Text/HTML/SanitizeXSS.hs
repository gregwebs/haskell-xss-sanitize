module Text.HTML.SanitizeXSS where

import Text.HTML.TagSoup

import Data.Set (Set(), member, fromList)
import Data.Char ( toLower, isAscii )

import Network.URI ( parseURIReference, URI (..),
                     isAllowedInURI, escapeURIString, unEscapeString, uriScheme )
import Codec.Binary.UTF8.String ( encodeString, decodeString )

sanitizeXSS :: String -> String
sanitizeXSS = renderTagsOptions renderOptions {
    optMinimize = \x -> x `elem` ["br","img"]
  } .  safeTags . parseTags -- Options parseOptions { optTagPosition = True }
  where
    safeTags :: [Tag String] -> [Tag String]
    safeTags [] = []
    safeTags (t@(TagClose name):tags) | safeTagName name = t:(safeTags tags)
                                      | otherwise = safeTags tags
    safeTags (TagOpen name attributes:tags)
      | safeTagName name = TagOpen name (filter safeAttribute attributes) : safeTags tags
      | otherwise = safeTags tags
    safeTags (t:tags) = t:safeTags tags

safeTagName :: String -> Bool
safeTagName tagname = tagname `member` sanitaryTags

safeAttribute :: (String, String) -> Bool
safeAttribute (name, value) = name `member` sanitaryAttributes &&
  (name `notElem` ["href","src"] || sanitaryURI value)
         

-- | Returns @True@ if the specified URI is not a potential security risk.
sanitaryURI :: String -> Bool
sanitaryURI u =
  case parseURIReference (escapeURI u) of
     Just p  -> (map toLower $ uriScheme p) `member` safeURISchemes
     Nothing -> False


-- | Escape unicode characters in a URI.  Characters that are
-- already valid in a URI, including % and ?, are left alone.
escapeURI :: String -> String
escapeURI = escapeURIString isAllowedInURI . encodeString

-- | Unescape unicode and some special characters in a URI, but
-- without introducing spaces.
unescapeURI :: String -> String
unescapeURI = escapeURIString (\c -> isAllowedInURI c || not (isAscii c)) .
               decodeString . unEscapeString



safeURISchemes :: Set String
safeURISchemes = fromList [ "", "http:", "https:", "ftp:", "mailto:", "file:",
             "telnet:", "gopher:", "aaa:", "aaas:", "acap:", "cap:", "cid:",
             "crid:", "dav:", "dict:", "dns:", "fax:", "go:", "h323:", "im:",
             "imap:", "ldap:", "mid:", "news:", "nfs:", "nntp:", "pop:",
             "pres:", "sip:", "sips:", "snmp:", "tel:", "urn:", "wais:",
             "xmpp:", "z39.50r:", "z39.50s:", "aim:", "callto:", "cvs:",
             "ed2k:", "feed:", "fish:", "gg:", "irc:", "ircs:", "lastfm:",
             "ldaps:", "magnet:", "mms:", "msnim:", "notes:", "rsync:",
             "secondlife:", "skype:", "ssh:", "sftp:", "smb:", "sms:",
             "snews:", "webcal:", "ymsgr:"]

sanitaryTags :: Set String
sanitaryTags = fromList ["a", "abbr", "acronym", "address", "area", "b", "big",
                "blockquote", "br", "button", "caption", "center",
                "cite", "code", "col", "colgroup", "dd", "del", "dfn",
                "dir", "div", "dl", "dt", "em", "fieldset", "font",
                "form", "h1", "h2", "h3", "h4", "h5", "h6", "hr",
                "i", "img", "input", "ins", "kbd", "label", "legend",
                "li", "map", "menu", "ol", "optgroup", "option", "p",
                "pre", "q", "s", "samp", "select", "small", "span",
                "strike", "strong", "sub", "sup", "table", "tbody",
                "td", "textarea", "tfoot", "th", "thead", "tr", "tt",
                "u", "ul", "var"]

sanitaryAttributes :: Set String
sanitaryAttributes = fromList ["abbr", "accept", "accept-charset",
                      "accesskey", "action", "align", "alt", "axis",
                      "border", "cellpadding", "cellspacing", "char",
                      "charoff", "charset", "checked", "cite", "class",
                      "clear", "cols", "colspan", "color", "compact",
                      "coords", "datetime", "dir", "disabled",
                      "enctype", "for", "frame", "headers", "height",
                      "href", "hreflang", "hspace", "id", "ismap",
                      "label", "lang", "longdesc", "maxlength", "media",
                      "method", "multiple", "name", "nohref", "noshade",
                      "nowrap", "prompt", "readonly", "rel", "rev",
                      "rows", "rowspan", "rules", "scope", "selected",
                      "shape", "size", "span", "src", "start",
                      "summary", "tabindex", "target", "title", "type",
                      "usemap", "valign", "value", "vspace", "width"]
