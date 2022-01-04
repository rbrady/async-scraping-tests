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


def pydantic_main():
    v = PVulnerability(**model_data)
    print(v.json())


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
    print("--- %s seconds ---" % (time.time() - start_time))

    p_start_time = time.time()
    pydantic_main()
    print("--- %s seconds ---" % (time.time() - p_start_time))

