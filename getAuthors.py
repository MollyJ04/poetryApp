import requests

response = requests.get("https://poetrydb.org/title")
response = response.json()
poems = response["titles"]
poemAuthors = {}
for i in poems:
    response = requests.get(f"https://poetrydb.org/title/{i}:abs")
    response = response.json()
    author = response[0]["author"]
    if author in poemAuthors.keys():
        print("that's already there")
    else:
        poemAuthors[i] = author
        print("Added " + author + "'s poem " + i)
with open("authorDictionary.txt","w") as file:
    file.append(poemAuthors)