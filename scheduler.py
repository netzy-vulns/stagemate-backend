from models import Song, PerformanceConfig, StageResult, ScheduleResult
from typing import List, Dict
from itertools import permutations


def calculate_schedule(config: PerformanceConfig) -> ScheduleResult:
    songs = config.songs
    if len(songs) <= 8:
        best_order, best_warnings = _brute_force(songs, config)
    else:
        best_order, best_warnings = _greedy(songs, config)

    stages = _build_timeline(best_order, config)
    total_time = stages[-1].end_time if stages else 0
    is_valid = len(best_warnings) == 0

    return ScheduleResult(
        stages=stages,
        warnings=best_warnings,
        total_time=total_time,
        is_valid=is_valid
    )


def _brute_force(songs: List[Song], config: PerformanceConfig):
    best_order = list(songs)
    best_warnings = _check_warnings(songs, config)
    best_score = _score(list(songs), config)

    for perm in permutations(songs):
        if _has_zero_intro_conflict(list(perm)):
            continue
        warnings = _check_warnings(list(perm), config)
        score = _score(list(perm), config)
        if score < best_score:
            best_score = score
            best_order = list(perm)
            best_warnings = warnings
        if score == 0:
            break

    return best_order, best_warnings


def _greedy(songs: List[Song], config: PerformanceConfig):
    remaining = songs.copy()
    order = []

    while remaining:
        if not order:
            next_song = max(remaining, key=lambda s: len(s.members))
        else:
            last_members = set(order[-1].members)
            last_intro_zero = order[-1].intro_time == 0
            if last_intro_zero:
                # 소개없는 곡 뒤엔 멤버 안 겹치는 곡 강제 배치
                non_overlap = [s for s in remaining
                               if not set(s.members) & last_members]
                next_song = non_overlap[0] if non_overlap else remaining[0]
            else:
                non_conflict = [s for s in remaining
                                if not set(s.members) & last_members]
                next_song = non_conflict[0] if non_conflict else remaining[0]

        order.append(next_song)
        remaining.remove(next_song)

    warnings = _check_warnings(order, config)
    return order, warnings


def _has_zero_intro_conflict(order: List[Song]) -> bool:
    for i in range(len(order) - 1):
        current = order[i]
        next_song = order[i + 1]
        if current.intro_time == 0:
            overlap = set(current.members) & set(next_song.members)
            if overlap:
                return True
    return False


def _score(order: List[Song], config: PerformanceConfig) -> float:
    warnings = _check_warnings(order, config)
    total_shortage = 0.0
    member_last_end: Dict[str, float] = {}
    current_time = 0.0

    for song in order:
        stage_start = current_time
        stage_end = stage_start + song.duration
        for member in song.members:
            if member in member_last_end:
                gap = stage_start - member_last_end[member]
                if gap < config.min_change_time:
                    total_shortage += (config.min_change_time - gap)
            member_last_end[member] = stage_end
        current_time = stage_end + song.intro_time

    return len(warnings) * 100 + total_shortage


def _check_warnings(order: List[Song], config: PerformanceConfig) -> List[str]:
    warnings = []
    member_last_end: Dict[str, float] = {}
    member_last_stage: Dict[str, str] = {}   # 멤버별 마지막 출연 곡 제목
    current_time = 0.0

    for i, song in enumerate(order):
        stage_start = current_time
        stage_end = stage_start + song.duration

        for member in song.members:
            if member in member_last_end:
                gap = stage_start - member_last_end[member]
                if gap < config.min_change_time:
                    shortage = round(config.min_change_time - gap, 1)
                    prev_title = member_last_stage[member]

                    # 사이에 있는 무대들 찾기 (소개 시간 조정 대상)
                    prev_idx = next(
                        j for j, s in enumerate(order)
                        if s.title == prev_title
                    )
                    between_stages = order[prev_idx:i]  # 사이 무대들

                    # 소개시간 조정으로 해결 가능한지 계산
                    current_intro_sum = sum(s.intro_time for s in between_stages)
                    needed_intro_sum = current_intro_sum + shortage

                    # 게임/이벤트 시간 계산 (분 → 분:초)
                    game_min = int(shortage)
                    game_sec = int((shortage - game_min) * 60)
                    game_str = f"{game_min}분" if game_sec == 0 else f"{game_min}분 {game_sec}초"

                    warning_msg = (
                        f"⚠️ [{member}]  "
                        f"'{prev_title}' → '{song.title}' 사이 "
                        f"여유 {gap:.1f}분 ({shortage}분 부족)\n"
                        f"  💡 해결 방법:\n"
                        f"  ① '{prev_title}' 또는 '{song.title}' 곡 길이를 {shortage}분 조정\n"
                        f"  ② 사이 무대 소개 시간 합계를 {needed_intro_sum:.1f}분 이상으로 늘리기\n"
                        f"  ③ 사이에 {game_str}짜리 게임/이벤트/멘트 추가"
                    )
                    warnings.append(warning_msg)

            member_last_end[member] = stage_end
            member_last_stage[member] = song.title

        current_time = stage_end + song.intro_time

    return warnings


def _build_timeline(order: List[Song], config: PerformanceConfig) -> List[StageResult]:
    stages = []
    current_time = 0.0

    for i, song in enumerate(order):
        start = current_time
        end = start + song.duration
        stages.append(StageResult(
            order=i + 1,
            song=song,
            start_time=round(start, 2),
            end_time=round(end, 2)
        ))
        current_time = end + song.intro_time

    return stages
