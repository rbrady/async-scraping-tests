import aiohttp
import time
import re
from collections import namedtuple
import asyncio

from bs4 import BeautifulSoup as bs
import xmltodict

from decorators import profile

rss_file = 'https://alas.aws.amazon.com/AL2/alas.rss'
html_file = 'https://alas.aws.amazon.com/alas2.html'

AlasSummary = namedtuple("AlasSummary", ["id", "url", "sev", "cves"])
AlasFixedIn = namedtuple("AlasFixedIn", ["pkg", "ver"])

title_pattern = re.compile(r"([^\s]+)\s+\(([^\)]+)\):.*")
whitespace_pattern = re.compile(r"\s")

severity_map = {
    "low": "Low",
    "medium": "Medium",
    "important": "High",
    "critical": "Critical",
}

amazon_security_advisories = {
    # '1': 'https://alas.aws.amazon.com/alas.rss',
    "2": "https://alas.aws.amazon.com/AL2/alas.rss"
}


# async def get_package_name_version(pkg):
#     if not pkg or not isinstance(pkg, str):
#         raise ValueError("Invalid package name: {}".format(pkg))
#
#     if not pkg.endswith(".rpm"):
#         pkg = pkg + ".rpm"
#
#     # name, version, release, epoch, arch = split_rpm_filename(pkg)
#
#     if release:
#         return AlasFixedIn(pkg=name, ver=(version + "-" + release))
#     else:
#         return AlasFixedIn(pkg=name, ver=version)


async def download(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            # print(resp.status)
            ret = await resp.text()
            return ret


async def get_summary(item):
    # # process title
    found = re.search(title_pattern, item.get('title').strip())
    alas_id = found.group(1)
    sev = found.group(2)
    # process description
    description = item.get('description')
    cves = (re.sub(whitespace_pattern, "", description).split(',')
            if description else [])
    url = item.get('link').strip()
    return AlasSummary(id=alas_id, url=url, sev=sev, cves=cves)


async def process_summary(item):
    summary = await get_summary(item)
    # download the summary
    item_html = await download(summary.url)
    # get fixes for summary
    item_fixes = await get_fixes_for_html(item_html)
    return summary, item_fixes


async def get_summary_items(url):
    # download the summary_list
    content = await download(url)
    rss_dict = xmltodict.parse(content)
    # for each item in the parse(summary_list)
    downloads = [f'http://someapp.com/{r}' for r in range(1, 11)]
    for fut in asyncio.as_completed([process_summary(item) for item in rss_dict['rss']['channel']['item']]):
        try:
            summary, fixes = await fut
            yield summary, fixes
        except Exception as err:
            print(err)


async def get_fixes_for_html(alas_html):
    arch_patterns = [r'src\b.+\.src', r'noarch\b.+\.noarch', r'x86_64\b.+\.x86_64']
    # parse alas html for fixes
    s = bs(alas_html)
    npdivs = [div for div in s.find_all(['div'])
              if div.attrs and div.attrs.get('id') == 'new_packages']
    fixes = []
    if len(npdivs) > 0:
        data = npdivs[0].text.replace(u'\xa0', u' ').strip()
        for arch_pattern in arch_patterns:
            found = re.search(arch_pattern, data)
            if found:
                # add package_name.arch to fixes
                fixes.append(found.group(0).replace(' ', '').split(':')[1])
                # fixed_in = {get_package_name_version(pkg_name) for pkg_name in fixes}

    return fixes


async def items():
    for version, url in amazon_security_advisories.items():
        async for summary, fixes in get_summary_items(url):
            # yield map_to_vulnerability(version, alas, fixed_in)
            yield {'version': version, 'alas': summary, 'fixes': fixes}


async def main():
    summary_count = 0

    print('starting amazon async driver')
    start_time = time.time()
    async for item in items():
        summary_count += 1
        print(item.get('alas').id)

    print("--- %s seconds ---" % (time.time() - start_time))

    print(f'--processed {summary_count} summaries.')


if __name__ == '__main__':
    """
    first run:
    --processed 739 summaries.
    --- 405.5903763771057 seconds ---
    
    second run:
    --processed 739 summaries.
    --- 410.65708470344543 seconds ---
    """
    # start_time = time.time()
    asyncio.run(main())
    # print("--- %s seconds ---" % (time.time() - start_time))

