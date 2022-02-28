from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import AsyncGenerator, List, Optional

import uvloop
import xmltodict
from pydantic import BaseModel, Field, validator
from selectolax.parser import HTMLParser as SHTMLParser

from utils import download_remote_file, split_rpm_filename

amazon_security_advisories = {
    # '1': 'https://alas.aws.amazon.com/alas.rss',
    "2": "https://alas.aws.amazon.com/AL2/alas.rss"
}

driver_workspace = Path("/tmp/amazon3")


# Pydantic Models
class AlasFixedIn(BaseModel):
    pkg: str = Field(..., alias="name")
    ver: str = Field(..., alias="name")

    @validator("pkg", pre=True)
    def pkg_ends_with_rpm(cls, v):
        if v:
            if not v.endswith(".rpm"):
                return f"{v}.rpm"
        return None

    @validator("ver", pre=True)
    def transform_release(cls, v):
        if v:
            name, version, release, epoch, arch = split_rpm_filename(v)
            if release:
                return f"{version}-{release}"
            return version
        return None


class Summary(BaseModel):
    id: Optional[str] = Field(..., alias="title")
    sev: Optional[str] = Field(..., alias="title")
    cves: Optional[List[str]] = Field(..., alias="description")
    url: str = Field(..., alias="link")
    fixes: Optional[List[AlasFixedIn]] = None

    @validator("cves", pre=True)
    def cves_from_description(cls, v):
        if v:
            return v.split(", ")
        return []

    @validator("id", pre=True)
    def id_from_title(cls, v):
        if v:
            return v.split(" ")[0]
        return None

    @validator("sev", pre=True)
    def sev_from_title(cls, v):
        if v:
            return v.split(" ")[1].translate(str.maketrans("", "", "!@#$():"))
        return None

    @classmethod
    async def async_parse(cls, data):
        return cls.parse_obj(data)


# New Feed Driver
class AmazonFeedDriver:
    def __init__(self, workspace: Path):
        self.workspace = workspace

    async def items(self):
        for version, url in amazon_security_advisories.items():
            # for each list of summaries returned by the url
            async for summary in self.extract(url, version):
                # for each list of summaries returned by the url
                yield summary

    @staticmethod
    async def find_packages(pattern, text):
        return re.search(pattern, text)

    async def get_fixes_for_html(self, alas_html):
        """This method takes up to 24 secs for execution"""
        arch_patterns = [r"src\b.+\.src", r"noarch\b.+\.noarch", r"x86_64\b.+\.x86_64"]
        fixes = []
        # parse alas html for fixes
        tree = SHTMLParser(alas_html)
        if data := tree.body.select("#new_packages").matches[0]:
            np_div = data.text().replace("\xa0", " ").strip()
            for fut in asyncio.as_completed(
                [
                    self.find_packages(arch_pattern, np_div)
                    for arch_pattern in arch_patterns
                ]
            ):
                found = await fut
                if found:
                    # add package_name.arch to fixes
                    fixes.append(
                        AlasFixedIn.parse_obj(
                            {"name": found.group(0).split(":")[1].strip()}
                        )
                    )
        return fixes

    async def process_summary(self, item):
        summary_start_time = time.time()
        summary = await Summary.async_parse(item)
        summary_time = time.time() - summary_start_time
        # download the summary
        html_start_time = time.time()
        summary_html = await download_remote_file(
            summary.url, self.workspace / "html" / summary.id
        )
        html_time = time.time() - html_start_time
        # get fixes for summary
        fixes_start_time = time.time()
        fixes = await self.get_fixes_for_html(summary_html)
        summary.fixes = fixes
        fixes_time = time.time() - fixes_start_time
        print(
            f"processing summary: {summary.id} - summary: {summary_time}, html: {html_time}, fixes: {fixes_time}"
        )
        return summary

    async def extract(self, url: str, version: int) -> AsyncGenerator:
        dl_start_time = time.time()
        content = await download_remote_file(url, self.workspace / f"{version}_rss.xml")
        download_time = time.time() - dl_start_time
        parse_start_time = time.time()
        rss_dict = xmltodict.parse(content)
        parse_time = time.time() - parse_start_time
        print(f"download time: {download_time}")
        print(f"parse time: {parse_time}")
        for fut in asyncio.as_completed(
            [self.process_summary(item) for item in rss_dict["rss"]["channel"]["item"]]
        ):
            try:
                result = await fut
                yield result
            except Exception as err:
                print(err)


async def main():
    summary_count = 0

    print("starting amazon3 async driver")
    start_time = time.time()
    afd = AmazonFeedDriver(driver_workspace)
    async for item in afd.items():
        print(item.id)  # change-me

    print("--- %s seconds ---" % (time.time() - start_time))

    print(f"--processed {summary_count} summaries.")


if __name__ == "__main__":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.run(main())
