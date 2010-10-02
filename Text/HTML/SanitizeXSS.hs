module Text.HTML.SanitizeXSS (sanitizeXSS) where

import Text.HTML.TagSoup

import Data.Set (Set(), member, notMember, (\\), fromList)
import Data.Char ( toLower )

import Network.URI ( parseURIReference, URI (..),
                     isAllowedInURI, escapeURIString, uriScheme )
import Codec.Binary.UTF8.String ( encodeString )

-- | santize the html to prevent XSS attacks. See README.md <http://github.com/gregwebs/haskell-xss-sanitize> for more details
sanitizeXSS :: String -> String
sanitizeXSS = renderTagsOptions renderOptions {
    optMinimize = \x -> x `elem` ["br","img"] -- <img><img> converts to <img />, <a/> converts to <a></a>
  } .  safeTags . parseTags
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
  (name `notMember` attrValIsUri || sanitaryURI value)
         

-- | Returns @True@ if the specified URI is not a potential security risk.
sanitaryURI :: String -> Bool
sanitaryURI u =
  case parseURIReference (escapeURI u) of
     Just p  -> (init (map toLower $ uriScheme p)) `member` safeURISchemes
     Nothing -> False


-- | Escape unicode characters in a URI.  Characters that are
-- already valid in a URI, including % and ?, are left alone.
escapeURI :: String -> String
escapeURI = escapeURIString isAllowedInURI . encodeString

safeURISchemes :: Set String
safeURISchemes = fromList acceptable_protocols

sanitaryTags :: Set String
sanitaryTags = fromList (acceptable_elements ++ mathml_elements ++ svg_elements)
  \\ (fromList svg_allow_local_href) -- extra filtering not implemented

sanitaryAttributes :: Set String
sanitaryAttributes = fromList (acceptable_attributes ++ mathml_attributes ++ svg_attributes)
  \\ (fromList svg_attr_val_allows_ref) -- extra unescaping not implemented

attrValIsUri :: Set String
attrValIsUri = fromList ["href", "src", "cite", "action", "longdesc",
    "xlink:href", "xml:base"]

acceptable_elements :: [String]
acceptable_elements = ["a", "abbr", "acronym", "address", "area",
    "article", "aside", "audio", "b", "big", "blockquote", "br", "button",
    "canvas", "caption", "center", "cite", "code", "col", "colgroup",
    "command", "datagrid", "datalist", "dd", "del", "details", "dfn",
    "dialog", "dir", "div", "dl", "dt", "em", "event-source", "fieldset",
    "figure", "footer", "font", "form", "header", "h1", "h2", "h3", "h4",
    "h5", "h6", "hr", "i", "img", "input", "ins", "keygen", "kbd",
    "label", "legend", "li", "m", "map", "menu", "meter", "multicol",
    "nav", "nextid", "ol", "output", "optgroup", "option", "p", "pre",
    "progress", "q", "s", "samp", "section", "select", "small", "sound",
    "source", "spacer", "span", "strike", "strong", "sub", "sup", "table",
    "tbody", "td", "textarea", "time", "tfoot", "th", "thead", "tr", "tt",
    "u", "ul", "var", "video"]
  
mathml_elements :: [String]
mathml_elements = ["maction", "math", "merror", "mfrac", "mi",
    "mmultiscripts", "mn", "mo", "mover", "mpadded", "mphantom",
    "mprescripts", "mroot", "mrow", "mspace", "msqrt", "mstyle", "msub",
    "msubsup", "msup", "mtable", "mtd", "mtext", "mtr", "munder",
    "munderover", "none"]

-- this should include altGlyph I think
svg_elements :: [String]
svg_elements = ["a", "animate", "animateColor", "animateMotion",
    "animateTransform", "clipPath", "circle", "defs", "desc", "ellipse",
    "font-face", "font-face-name", "font-face-src", "g", "glyph", "hkern",
    "linearGradient", "line", "marker", "metadata", "missing-glyph",
    "mpath", "path", "polygon", "polyline", "radialGradient", "rect",
    "set", "stop", "svg", "switch", "text", "title", "tspan", "use"]
  
acceptable_attributes :: [String]
acceptable_attributes = ["abbr", "accept", "accept-charset", "accesskey",
    "action", "align", "alt", "autocomplete", "autofocus", "axis",
    "background", "balance", "bgcolor", "bgproperties", "border",
    "bordercolor", "bordercolordark", "bordercolorlight", "bottompadding",
    "cellpadding", "cellspacing", "ch", "challenge", "char", "charoff",
    "choff", "charset", "checked", "cite", "class", "clear", "color",
    "cols", "colspan", "compact", "contenteditable", "controls", "coords",
    -- "data", TODO: allow this with further filtering
    "datafld", "datapagesize", "datasrc", "datetime", "default",
    "delay", "dir", "disabled", "draggable", "dynsrc", "enctype", "end",
    "face", "for", "form", "frame", "galleryimg", "gutter", "headers",
    "height", "hidefocus", "hidden", "high", "href", "hreflang", "hspace",
    "icon", "id", "inputmode", "ismap", "keytype", "label", "leftspacing",
    "lang", "list", "longdesc", "loop", "loopcount", "loopend",
    "loopstart", "low", "lowsrc", "max", "maxlength", "media", "method",
    "min", "multiple", "name", "nohref", "noshade", "nowrap", "open",
    "optimum", "pattern", "ping", "point-size", "prompt", "pqg",
    "radiogroup", "readonly", "rel", "repeat-max", "repeat-min",
    "replace", "required", "rev", "rightspacing", "rows", "rowspan",
    "rules", "scope", "selected", "shape", "size", "span", "src", "start",
    "step",
    -- "style", TODO: allow this with further filtering
    "summary", "suppress", "tabindex", "target",
    "template", "title", "toppadding", "type", "unselectable", "usemap",
    "urn", "valign", "value", "variable", "volume", "vspace", "vrml",
    "width", "wrap", "xml:lang"]

acceptable_protocols :: [String]
acceptable_protocols = [ "ed2k", "ftp", "http", "https", "irc",
    "mailto", "news", "gopher", "nntp", "telnet", "webcal",
    "xmpp", "callto", "feed", "urn", "aim", "rsync", "tag",
    "ssh", "sftp", "rtsp", "afs" ]

mathml_attributes :: [String]
mathml_attributes = ["actiontype", "align", "columnalign", "columnalign",
    "columnalign", "columnlines", "columnspacing", "columnspan", "depth",
    "display", "displaystyle", "equalcolumns", "equalrows", "fence",
    "fontstyle", "fontweight", "frame", "height", "linethickness", "lspace",
    "mathbackground", "mathcolor", "mathvariant", "mathvariant", "maxsize",
    "minsize", "other", "rowalign", "rowalign", "rowalign", "rowlines",
    "rowspacing", "rowspan", "rspace", "scriptlevel", "selection",
    "separator", "stretchy", "width", "width", "xlink:href", "xlink:show",
    "xlink:type", "xmlns", "xmlns:xlink"]

svg_attributes :: [String]
svg_attributes = ["accent-height", "accumulate", "additive", "alphabetic",
    "arabic-form", "ascent", "attributeName", "attributeType",
    "baseProfile", "bbox", "begin", "by", "calcMode", "cap-height",
    "class", "clip-path", "color", "color-rendering", "content", "cx",
    "cy", "d", "dx", "dy", "descent", "display", "dur", "end", "fill",
    "fill-opacity", "fill-rule", "font-family", "font-size",
    "font-stretch", "font-style", "font-variant", "font-weight", "from",
    "fx", "fy", "g1", "g2", "glyph-name", "gradientUnits", "hanging",
    "height", "horiz-adv-x", "horiz-origin-x", "id", "ideographic", "k",
    "keyPoints", "keySplines", "keyTimes", "lang", "marker-end",
    "marker-mid", "marker-start", "markerHeight", "markerUnits",
    "markerWidth", "mathematical", "max", "min", "name", "offset",
    "opacity", "orient", "origin", "overline-position",
    "overline-thickness", "panose-1", "path", "pathLength", "points",
    "preserveAspectRatio", "r", "refX", "refY", "repeatCount",
    "repeatDur", "requiredExtensions", "requiredFeatures", "restart",
    "rotate", "rx", "ry", "slope", "stemh", "stemv", "stop-color",
    "stop-opacity", "strikethrough-position", "strikethrough-thickness",
    "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap",
    "stroke-linejoin", "stroke-miterlimit", "stroke-opacity",
    "stroke-width", "systemLanguage", "target", "text-anchor", "to",
    "transform", "type", "u1", "u2", "underline-position",
    "underline-thickness", "unicode", "unicode-range", "units-per-em",
    "values", "version", "viewBox", "visibility", "width", "widths", "x",
    "x-height", "x1", "x2", "xlink:actuate", "xlink:arcrole",
    "xlink:href", "xlink:role", "xlink:show", "xlink:title", "xlink:type",
    "xml:base", "xml:lang", "xml:space", "xmlns", "xmlns:xlink", "y",
    "y1", "y2", "zoomAndPan"]

-- the values for these need to be escaped
svg_attr_val_allows_ref :: [String]
svg_attr_val_allows_ref = ["clip-path", "color-profile", "cursor", "fill",
    "filter", "marker", "marker-start", "marker-mid", "marker-end",
    "mask", "stroke"]

svg_allow_local_href :: [String]
svg_allow_local_href = ["altGlyph", "animate", "animateColor",
    "animateMotion", "animateTransform", "cursor", "feImage", "filter",
    "linearGradient", "pattern", "radialGradient", "textpath", "tref",
    "set", "use"]

{- style value (css) filtering not implemented
 -
 - this is used for css filtering
allowed_svg_properties = fromList acceptable_svg_properties
acceptable_svg_properties = [ "fill", "fill-opacity", "fill-rule",
    "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin",
    "stroke-opacity"]


allowed_css_properties = fromList acceptable_css_properties
allowed_css_keywords = fromList acceptable_css_keywords
acceptable_css_properties = ["azimuth", "background-color",
    "border-bottom-color", "border-collapse", "border-color",
    "border-left-color", "border-right-color", "border-top-color", "clear",
    "color", "cursor", "direction", "display", "elevation", "float", "font",
    "font-family", "font-size", "font-style", "font-variant", "font-weight",
    "height", "letter-spacing", "line-height", "overflow", "pause",
    "pause-after", "pause-before", "pitch", "pitch-range", "richness",
    "speak", "speak-header", "speak-numeral", "speak-punctuation",
    "speech-rate", "stress", "text-align", "text-decoration", "text-indent",
    "unicode-bidi", "vertical-align", "voice-family", "volume",
    "white-space", "width"]
acceptable_css_keywords = ["auto", "aqua", "black", "block", "blue",
    "bold", "both", "bottom", "brown", "center", "collapse", "dashed",
    "dotted", "fuchsia", "gray", "green", "!important", "italic", "left",
    "lime", "maroon", "medium", "none", "navy", "normal", "nowrap", "olive",
    "pointer", "purple", "red", "right", "solid", "silver", "teal", "top",
    "transparent", "underline", "white", "yellow"]
-}


-- I don't know where this is from!
-- The rest of pandoc's lists were smaller than the ones in html5lib
-- This one is bigger.
{-
pandoc_acceptable_protocols = [ "", "http:", "https:", "ftp:", "mailto:", "file:",
             "telnet:", "gopher:", "aaa:", "aaas:", "acap:", "cap:", "cid:",
             "crid:", "dav:", "dict:", "dns:", "fax:", "go:", "h323:", "im:",
             "imap:", "ldap:", "mid:", "news:", "nfs:", "nntp:", "pop:",
             "pres:", "sip:", "sips:", "snmp:", "tel:", "urn:", "wais:",
             "xmpp:", "z39.50r:", "z39.50s:", "aim:", "callto:", "cvs:",
             "ed2k:", "feed:", "fish:", "gg:", "irc:", "ircs:", "lastfm:",
             "ldaps:", "magnet:", "mms:", "msnim:", "notes:", "rsync:",
             "secondlife:", "skype:", "ssh:", "sftp:", "smb:", "sms:",
             "snews:", "webcal:", "ymsgr:"]
-}
