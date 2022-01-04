import time

from decorators import profile
from models import PVulnerability, PFixedIn, Vulnerability, FixedIn, JsonifierMixin

model_data = {
    'Name': "The Name",
    'NamespaceName': "The Namespace Name",
    'Description': "this is my description",
    'Severity': 'Medium',
    'Metadata': {'CVE': ['CVE-555-1212']},
    'Link': 'https://supersecurity.io/supercereal',
    'FixedIn': [
        {
            'Name': "The Fixedin Name",
            'NamespaceName': "The FixedIn Namespace Name",
            'VersionFormat': 'rpm',
            'Version': '1.0.0',

        }
    ]
}


@profile
def pydantic_main():
    v = PVulnerability(**model_data)
    print(v.json())


@profile
def legacy_main():
    v = Vulnerability()
    v.Name = model_data['Name'],
    v.NamespaceName = model_data['NamespaceName'],
    v.Description = model_data['Description'],
    v.Severity = model_data['Severity'],
    v.Metadata = model_data['Metadata'],
    v.Link = model_data['Link']

    fi = FixedIn()
    fi.Name = model_data['FixedIn'][0]['Name']
    fi.NamespaceName = model_data['FixedIn'][0]['NamespaceName']
    fi.VersionFormat = model_data['FixedIn'][0]['VersionFormat']
    fi.Version = model_data['FixedIn'][0]['Version']

    v.FixedIn.append(fi)

    print(v.json())


if __name__ == '__main__':
    start_time = time.time()
    legacy_main()
    legacy_time = time.time() - start_time


    p_start_time = time.time()
    pydantic_main()
    p_time = time.time() - p_start_time

    print(f"Legacy --- {legacy_time} seconds ---")
    print(f"Pydantic --- {p_time} seconds ---")

    print("Legacy is faster: %s" % (legacy_time < p_time))
    print("Pydantic is faster: %s" % (p_time < legacy_time))


