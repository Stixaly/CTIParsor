/**
 * markdownImages — which images the report preview may draw.
 *
 * An image in a report is a request from the analyst's browser to whatever
 * address the report names: a tracking pixel learns the analyst's address, and
 * on an air-gapped machine the request just hangs. So only data: image URIs,
 * which carry their bytes inline, are drawn. Kept in its own module (no React
 * imports) so it can be unit-tested without rendering the preview.
 */
import { defaultUrlTransform } from 'react-markdown'
import type { UrlTransform } from 'react-markdown'

const DATA_IMAGE = /^data:image\//i

/** True when an image src is an inline data: image, the only kind the preview draws. */
export function isAllowedImageSrc(src: string | undefined): boolean {
  return src !== undefined && DATA_IMAGE.test(src)
}

/**
 * The react-markdown urlTransform: keeps a data: image for <img src>, and
 * leaves every other URL to react-markdown's default, which drops data: URLs.
 */
export const markdownUrlTransform: UrlTransform = (url, key, node) =>
  key === 'src' && node.tagName === 'img' && isAllowedImageSrc(url)
    ? url
    : defaultUrlTransform(url)
