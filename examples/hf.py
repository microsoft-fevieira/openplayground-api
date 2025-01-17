import requests

API_URL = "https://api-inference.huggingface.co/models/EleutherAI/pythia-12b-deduped-v0"
headers = {"Authorization": "Bearer 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"}

def query(payload):
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

output = query({
    "inputs": "You are an AI assistant that helps people find information. You will receive a task and think step by step. Then provide your final outcome following the regular expression 'Answer: [Rr]oom [0-9]+'\nuser: Imagine a world with twelve rooms. From the lobby you have two choices, room 1 and room 2. You enter room 1, at the end thereâ€™s a door that leads to room 3, and room 3 leads to room 5. There is a door in room 5 that leads to room 7 and room 7 leads to room 9. From room 9 you can enter room 11. Thereâ€™s a chest in room 11. You open it and there is 10 dollars, but you do not take any money, youâ€™re just learning about the environment. Then you exit and start over. This time in the lobby you choose room 2, then enter room 4, which leads to room 6. There is a door in room 6 that leads to room 8 and room 8 leads to room 10. At the end there is a door that leads to room 12. Thereâ€™s a chest with 50 dollars in room 12, but you do not take any money, youâ€™re just learning about the environment. You return to the lobby. You will only be able to choose one path that leads to the most money. Which room from the lobby will lead to the path where one can make the most money?",
})

print(output)