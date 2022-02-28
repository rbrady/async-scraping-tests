from html.parser import HTMLParser

import aiofiles
import httpx


async def download_remote_file(url, output_path, timeout: int = 125) -> str:
    """asynchronously downloads and stores a remote file"""
    # skip_if_exists moved out to a calling method because standard logger is blocking
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()  # will raise any 4xx or 5xx  response codes as exceptions
        async with aiofiles.open(output_path, "w") as fp:
            await fp.write(resp.text)
        return resp.text


def split_rpm_filename(rpm_filename):
    """
    Parse the components of an rpm filename and return them as a tuple: (name, version, release, epoch, arch)
    foo-1.0-1.x86_64.rpm -> foo, 1.0, 1, '', x86_64
    1:bar-9-123a.ia64.rpm -> bar, 9, 123a, 1, ia64
    :param rpm_filename: a string filename (not path) of an rpm file
    :returns: a tuple of the constituent parts compliant with RPM spec.
    """

    components = rpm_filename.rsplit(".rpm", 1)[0].rsplit(".", 1)
    arch = components.pop()

    rel_comp = components[0].rsplit("-", 2)
    release = rel_comp.pop()

    # Version
    version = rel_comp.pop()

    # Epoch
    epoch_comp = rel_comp[0].split(":", 1) if rel_comp else []
    if len(epoch_comp) == 1:
        epoch = ""
        name = epoch_comp[0]
    elif len(epoch_comp) > 1:
        epoch = epoch_comp[0]
        name = epoch_comp[1]
    else:
        epoch = None
        name = None

    return name, version, release, epoch, arch
