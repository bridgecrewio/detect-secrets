"""
The analytics module produces a machine-readable breakdown of true and false positives
for a given audited baseline.
"""
from collections import defaultdict
from typing import Any
from typing import cast
from typing import Dict

from ..core.plugins.util import get_mapping_from_secret_type_to_class
from ..core.potential_secret import PotentialSecret
from .common import get_baseline_from_file


def calculate_statistics_for_baseline(
    filename: str,
    **kwargs: Any,  # noqa: ARG001
) -> 'StatisticsAggregator':
    """
    :raises: InvalidBaselineError
    """
    secrets = get_baseline_from_file(filename)

    aggregator = StatisticsAggregator()
    for _, secret in secrets:
        # TODO: gather real secrets?
        # TODO: do we need repo_info?
        aggregator.record_secret(secret)

    return aggregator


class StatisticsAggregator:
    def __init__(self) -> None:
        framework = {
            'stats': StatisticsCounter,
        }

        self.data: Dict[str, Any] = defaultdict(
            lambda: {
                key: value()
                for key, value in framework.items()
            },
        )

    def record_secret(self, secret: PotentialSecret) -> None:
        # NOTE: We don't do anything with verified secrets, because this function
        # is solely to measure statistics on labelled results.
        counter = self._get_plugin_counter(secret.type)
        if secret.is_secret is True:
            counter.correct += 1
        elif secret.is_secret is False:
            counter.incorrect += 1
        else:
            counter.unknown += 1

    def _get_plugin_counter(self, secret_type: str) -> 'StatisticsCounter':
        return cast(StatisticsCounter, self.data[secret_type]['stats'])

    def __str__(self) -> str:
        raise NotImplementedError

    def json(self) -> Dict[str, Any]:
        output = {}
        for secret_type, framework in self.data.items():
            output[get_mapping_from_secret_type_to_class()[secret_type].__name__] = {
                key: value.json()
                for key, value in framework.items()
            }

        return output


class StatisticsCounter:
    def __init__(self) -> None:
        self.correct: int = 0
        self.incorrect: int = 0
        self.unknown: int = 0

    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}(correct={self.correct}, '
            'incorrect={self.incorrect}, unknown={self.unknown},)'
        )

    def json(self) -> Dict[str, Any]:
        precision = (
            round(float(self.correct) / (self.correct + self.incorrect), 4)
            if (self.correct and self.incorrect)
            else 0.0
        )

        # NOTE(2020-11-08|domanchi): This isn't the formal definition of `recall`, however,
        # this is the definition that we're going to attribute to it.
        #
        # Rationale: If we follow the formal definition of `recall` (i.e. TP / (TP + FN)),
        # we would need some way to measure false negatives. However, this is impossible
        # since we don't know what we don't know. The only way to get proper "recall" is
        # to measure this against a known set of secrets, and see how effective our rules
        # are against them.
        #
        # This is a common problem with Machine Learning. One way to address this is by
        # splitting the labelled data you have into a "test set" and a "training set",
        # train your model on the test set, and test it's performance on its counterpart.
        # This works great for RegexBasedDetectors, but not so much for more heuristic
        # scanners (e.g. entropy scanning, or keyword scanning). The primary reason is
        # that no labelled data that we can compile will be a representative sample of
        # the different types of secrets out there. And as such, we'd be overfitting it
        # to whatever sample set we attempt this with.
        #
        # There is however, an alternative method. If we know these ratios for a certain
        # configuration, then change the configuration to be more liberal, we would expect
        # our *precision* to decrease, and our *recall* to increase (i.e. catching more
        # false positives, in hopes to reduce false negatives). Then, we can work to
        # **increase** our precision with this same data set, which is a much more
        # measurable way to do this than "decreasing false negatives".
        #
        # Essentially, if we make our scans more liberal (catching more things), but
        # our precision stays the same, we would be catching more real secrets. This
        # definition of `recall` allows us to do this.
        recall = (
            round(float(self.correct) / (self.correct + self.unknown), 4)
            if (self.correct + self.unknown)
            else 0.0
        )

        return {
            'raw': {
                'true-positives': self.correct,
                'false-positives': self.incorrect,
                'unknown': self.unknown,
            },
            'score': {
                'precision': precision,
                'recall': recall,
            },
        }
