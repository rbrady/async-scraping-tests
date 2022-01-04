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
            print(resp.status)
            ret = await resp.text()
            return ret


async def get_summaries(url):
    content = await download(url)
    rss_dict = xmltodict.parse(content)
    for item in rss_dict['rss']['channel']['item']:
        # # process title
        found = re.search(title_pattern, item.get('title').strip())
        alas_id = found.group(1)
        sev = found.group(2)
        # process description
        description = item.get('description')
        cves = (re.sub(whitespace_pattern, "", description).split(',')
                if description else [])
        url = item.get('link').strip()
        yield AlasSummary(id=alas_id, url=url, sev=sev, cves=cves)


async def get_fixes(summary):
    arch_patterns = [r'src\b.+\.src', r'noarch\b.+\.noarch', r'x86_64\b.+\.x86_64']
    item_html = await download(summary.url)
    # parse alas html for fixes
    s = bs(item_html)
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
    # print(f'version: {version} alas: {summary.id} fixes: {fixes}')


@profile
async def items():
    for version, url in amazon_security_advisories.items():
        async for summary in get_summaries(url):
            fixes = await get_fixes(summary)
            # yield map_to_vulnerability(version, alas, fixed_in)
            yield f'version: {version} alas: {summary.id} fixes: {fixes}'


async def main():
    summary_count = 0

    async for item in items():
        summary_count += 1
        print(item)

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
    start_time = time.time()
    asyncio.run(main())
    print("--- %s seconds ---" % (time.time() - start_time))

