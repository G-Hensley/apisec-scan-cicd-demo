from colors import Colors


class Table:
    qual_counts: dict
    score_counts: dict
    method: list
    endpoint: list
    category_name: list
    test_name: list
    cvss_score: list
    cvss_qualifier: list
    description: list
    widths: list

    QUALS = ["Critical", "High", "Medium", "None"]
    TITLES = ["Method", "Endpoint", "Category", "Test Type", "Score", "Rating", "Description"]
    MAX_WIDTH = 100

    def __init__(self):
        self.qual_counts = {}
        self.score_counts = {}
        self.method = []
        self.endpoint = []
        self.category_name = []
        self.test_name = []
        self.cvss_score = []
        self.cvss_qualifier = []
        self.description = []
        self.widths = []

    def add_vulnerability(self, v:dict):
        if not isinstance(v, dict):
            return
        for f in (v.get('scanFindings') or []):
            if not isinstance(f, dict):
                continue
            test_result = f.get('testResult') or {}
            test_details = f.get('testDetails') or {}
            test_status = f.get('testStatus') or {}
            score = test_result.get('cvssScore')
            qual = test_result.get('cvssQualifier') or 'Unknown'
            self.increment_count(self.score_counts, str(score) if score is not None else 'unknown')
            self.increment_count(self.qual_counts, qual)
            self.add_row([v.get('method', ''),
                          v.get('resource', ''),
                          test_details.get('categoryName', ''),
                          test_details.get('categoryTestName', ''),
                          score if score is not None else '',
                          qual,
                          self.truncate(test_status.get('description', '') or '')])

    def increment_count(self, count:dict, key):
        if key not in count:
            count[key] = 1
        else:
            count[key] += 1

    def add_row(self, cells:list):
        self.method.append(cells[0])
        self.endpoint.append(cells[1])
        self.category_name.append(cells[2])
        self.test_name.append(cells[3])
        self.cvss_score.append(cells[4])
        self.cvss_qualifier.append(cells[5])
        self.description.append(cells[6])

    def get_data(self):
        self.widths = [self.width(self.method, self.TITLES[0]),
                       self.width(self.endpoint, self.TITLES[1]),
                       self.width(self.category_name, self.TITLES[2]),
                       self.width(self.test_name, self.TITLES[3]),
                       len(self.TITLES[4]),
                       self.width(self.cvss_qualifier, self.TITLES[5]),
                       self.MAX_WIDTH]
        return [self.TITLES] + list(zip(self.method,
                                        self.endpoint,
                                        self.category_name,
                                        self.test_name,
                                        self.cvss_score,
                                        self.cvss_qualifier,
                                        self.description))

    def width(self, column:list, title:str):
        if not column:
            return len(title)
        return max(len(max([str(c) for c in column], key=len)), len(title))

    def truncate(self, text:str):
        return (text[:self.MAX_WIDTH-3] + "...") if len(text) > self.MAX_WIDTH else text

    def color(self, qual:str):
        match qual:
            case "Critical":
                return Colors.RED
            case "High":
                return Colors.RED
            case "Medium":
                return Colors.YELLOW
            case "None":
                return Colors.GREEN
            case _:
                return Colors.END

    def color_qual(self, qual:str):
        return f"{self.color(qual)}{qual}{Colors.END}"

    def color_score(self, score:float, qual:str):
        return f"{self.color(qual)}{str(score)}{Colors.END}"
