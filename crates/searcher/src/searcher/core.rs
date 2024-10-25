use bstr::ByteSlice;

use grep_matcher::{LineMatchKind, Matcher};

use crate::{
    line_buffer::BinaryDetection,
    lines::{self, LineStep},
    searcher::{Config, Range, Searcher},
    sink::{
        Sink, SinkContext, SinkContextKind, SinkError, SinkFinish, SinkMatch,
    },
};

enum FastMatchResult {
    Continue,
    Stop,
    SwitchToSlow,
}

/// 注：核心驱动，包装了matcher & searcher & sink，即输入、匹配、输出整个流量
/// 调用过程：begin() -> while( fill() -> match_by_line() ) -> finish()
#[derive(Debug)]
pub(crate) struct Core<'s, M: 's, S> {
    /// 注：searcher配置
    config: &'s Config,
    matcher: M,
    searcher: &'s Searcher,
    sink: S,
    /// 注：是否为二进制
    binary: bool,
    /// 注：记录读取的位置
    /// 作用于每次roll内的状态，每次roll，会计算可以处理的行range，pos用于标记可处理range的右边界offset
    pos: usize,
    /// 注：全局统计的offset
    absolute_byte_offset: u64,
    /// 注：如果检测到二进制字符，则存储该字符的offset
    binary_byte_offset: Option<usize>,
    /// 注：如果开启输出line_number，则会保存检索已经行进的行号
    line_number: Option<u64>,
    /// 注：每次做line count时，存储已经count到的位置，用于作为下次count的起始offset
    /// 作用于每次roll内的状态，下一次roll被重置
    last_line_counted: usize,
    /// 注：记录在before after context过程中，对已经探测到的数据进行遍历时，控制前进的位置
    /// 等同于 记录已经完成sink发送进度，即还没有sink部分的offset
    /// 作用于每次roll内的状态，下一次roll被重置
    last_line_visited: usize,
    /// 注：标记向后探测多少行。这个标记逻辑很隐晦：
    /// 1. 在匹配后才复制，后面持续的遍历，如果匹配不成功，但该字段有值，则说明是需要级联输出，并递减该值
    /// 2. 如果在after_context范围内，又成功匹配，重置该值。
    after_context_left: usize,
    has_sunk: bool,
    has_matched: bool,
}

impl<'s, M: Matcher, S: Sink> Core<'s, M, S> {
    pub(crate) fn new(
        searcher: &'s Searcher,
        matcher: M,
        sink: S,
        binary: bool,
    ) -> Core<'s, M, S> {
        let line_number =
            if searcher.config.line_number { Some(1) } else { None };
        let core = Core {
            config: &searcher.config,
            matcher,
            searcher,
            sink,
            binary,
            pos: 0,
            absolute_byte_offset: 0,
            binary_byte_offset: None,
            line_number,
            last_line_counted: 0,
            last_line_visited: 0,
            after_context_left: 0,
            has_sunk: false,
            has_matched: false,
        };
        if !core.searcher.multi_line_with_matcher(&core.matcher) {
            if core.is_line_by_line_fast() {
                log::trace!("searcher core: will use fast line searcher");
            } else {
                log::trace!("searcher core: will use slow line searcher");
            }
        }
        core
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub(crate) fn binary_byte_offset(&self) -> Option<u64> {
        self.binary_byte_offset.map(|offset| offset as u64)
    }

    pub(crate) fn matcher(&self) -> &M {
        &self.matcher
    }

    pub(crate) fn matched(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        self.sink_matched(buf, range)
    }

    pub(crate) fn binary_data(
        &mut self,
        binary_byte_offset: u64,
    ) -> Result<bool, S::Error> {
        self.sink.binary_data(&self.searcher, binary_byte_offset)
    }

    pub(crate) fn begin(&mut self) -> Result<bool, S::Error> {
        self.sink.begin(&self.searcher)
    }

    pub(crate) fn finish(
        &mut self,
        byte_count: u64,
        binary_byte_offset: Option<u64>,
    ) -> Result<(), S::Error> {
        self.sink.finish(
            &self.searcher,
            &SinkFinish { byte_count, binary_byte_offset },
        )
    }

    pub(crate) fn match_by_line(
        &mut self,
        buf: &[u8],
    ) -> Result<bool, S::Error> {
        // 注：判断是否是常规的按行匹配模式，即fast模式
        if self.is_line_by_line_fast() {
            match self.match_by_line_fast(buf)? {
                FastMatchResult::SwitchToSlow => self.match_by_line_slow(buf),
                FastMatchResult::Continue => Ok(true),
                FastMatchResult::Stop => Ok(false),
            }
        } else {
            self.match_by_line_slow(buf)
        }
    }

    /// 注：传入的buf，即line_buffer中可读数据，计算buffer中offset向前可滚动的位置
    /// 正常情况下，因为buf里是完整行，如果已经读取，直接滚动到结尾即可
    /// 在有before|after context时，需要向前级联N行，所以此时滚动buf要留N行老数据
    pub(crate) fn roll(&mut self, buf: &[u8]) -> usize {
        // 注：self.config.max_context()就是查找需要向前、向后多关联匹配的最大行数
        let consumed = if self.config.max_context() == 0 {
            buf.len()
        } else {
            // It might seem like all we need to care about here is just
            // the "before context," but in order to sink the context
            // separator (when before_context==0 and after_context>0), we
            // need to know something about the position of the previous
            // line visited, even if we're at the beginning of the buffer.
            // 注：从后向前找max_context行数据，定位到起始offset
            // 从后往前是为了保证buffer里至少留max_context行老数据，用于before_context级联
            let context_start = lines::preceding(
                buf,
                self.config.line_term.as_byte(),
                self.config.max_context(),
            );
            let consumed =
                std::cmp::max(context_start, self.last_line_visited);
            consumed
        };
        // 注：统计已标记消费部分中的行数
        self.count_lines(buf, consumed);
        self.absolute_byte_offset += consumed as u64;
        self.last_line_counted = 0;
        self.last_line_visited = 0;
        self.set_pos(buf.len() - consumed);
        consumed
    }

    /// 注：是否检测到二进制字符，true表示检测到
    pub(crate) fn detect_binary(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        if self.binary_byte_offset.is_some() {
            return Ok(self.config.binary.quit_byte().is_some()); // 注：如果配置了停止符，返回true
        }
        // 注：从配置获取需要检测的二进制字符
        let binary_byte = match self.config.binary.0 {
            BinaryDetection::Quit(b) => b,
            BinaryDetection::Convert(b) => b,
            _ => return Ok(false),
        };
        // 注：计算range内，第一个二进制字符的offset
        if let Some(i) = buf[*range].find_byte(binary_byte) {
            let offset = range.start() + i;
            self.binary_byte_offset = Some(offset);
            if !self.binary_data(offset as u64)? {
                return Ok(true);
            }
            Ok(self.config.binary.quit_byte().is_some())
        } else {
            Ok(false)
        }
    }

    /// 注：向前级联N行，并且发送到sink
    pub(crate) fn before_context_by_line(
        &mut self,
        buf: &[u8],
        upto: usize,
    ) -> Result<bool, S::Error> {
        if self.config.before_context == 0 {
            return Ok(true);
        }
        let range = Range::new(self.last_line_visited, upto);
        if range.is_empty() {
            return Ok(true);
        }
        // 注：向前探测N行（before_context），找到起始offset
        let before_context_start = range.start()
            + lines::preceding(
                &buf[range],
                self.config.line_term.as_byte(),
                self.config.before_context - 1,
            );

        // 注：这里二次遍历需要探测的range
        let range = Range::new(before_context_start, range.end());
        let mut stepper = LineStep::new(
            self.config.line_term.as_byte(),
            range.start(),
            range.end(),
        );
        // 注：遍历级联出来的行
        while let Some(line) = stepper.next_match(buf) {
            // 注：检测不一致情况，如果有则发送中断给sink，sink返回false，则中断
            if !self.sink_break_context(line.start())? {
                return Ok(false);
            }
            // 注：向sink发送一行数据（before_context级联的行）
            if !self.sink_before_context(buf, &line)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn after_context_by_line(
        &mut self,
        buf: &[u8],
        upto: usize,
    ) -> Result<bool, S::Error> {
        if self.after_context_left == 0 {
            return Ok(true);
        }
        let range = Range::new(self.last_line_visited, upto);
        let mut stepper = LineStep::new(
            self.config.line_term.as_byte(),
            range.start(),
            range.end(),
        );
        while let Some(line) = stepper.next_match(buf) {
            if !self.sink_after_context(buf, &line)? {
                return Ok(false);
            }
            if self.after_context_left == 0 {
                break;
            }
        }
        Ok(true)
    }

    pub(crate) fn other_context_by_line(
        &mut self,
        buf: &[u8],
        upto: usize,
    ) -> Result<bool, S::Error> {
        let range = Range::new(self.last_line_visited, upto);
        let mut stepper = LineStep::new(
            self.config.line_term.as_byte(),
            range.start(),
            range.end(),
        );
        while let Some(line) = stepper.next_match(buf) {
            if !self.sink_other_context(buf, &line)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn match_by_line_slow(&mut self, buf: &[u8]) -> Result<bool, S::Error> {
        debug_assert!(!self.searcher.multi_line_with_matcher(&self.matcher));

        // 注：构造LineStep
        let range = Range::new(self.pos(), buf.len());
        let mut stepper = LineStep::new(
            self.config.line_term.as_byte(),
            range.start(),
            range.end(),
        );
        // 注：按行遍历buf
        while let Some(line) = stepper.next_match(buf) {
            let matched = {
                // Stripping the line terminator is necessary to prevent some
                // classes of regexes from matching the empty position *after*
                // the end of the line. For example, `(?m)^$` will match at
                // position (2, 2) in the string `a\n`.
                // 注：提取slice，不包含分隔符
                let slice = lines::without_terminator(
                    &buf[line],
                    self.config.line_term,
                );
                // 注：提交给matcher进行匹配
                match self.matcher.shortest_match(slice) {
                    Err(err) => return Err(S::Error::error_message(err)),
                    Ok(result) => result.is_some(),
                }
            };
            // 注：更新遍历offset进度
            self.set_pos(line.end());
            // 注：是否匹配成功
            let success = matched != self.config.invert_match;
            if success {
                self.has_matched = true;
                // 注：向前级联N行，并且发送到sink
                if !self.before_context_by_line(buf, line.start())? {
                    return Ok(false);
                }
                // 注：发送匹配行到sink
                if !self.sink_matched(buf, &line)? {
                    return Ok(false);
                }
            } else if self.after_context_left >= 1 {
                // 注：匹配不成功情况下，如果还在上一次成功匹配的after_context范围内，继续向sink输出
                if !self.sink_after_context(buf, &line)? {
                    return Ok(false);
                }
            } else if self.config.passthru {
                if !self.sink_other_context(buf, &line)? {
                    return Ok(false);
                }
            }
            if self.config.stop_on_nonmatch && !success && self.has_matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 注：快速匹配模式，优势是不是按行进行匹配，而是按buffer直接匹配，省去切分行的过程
    /// 整体还是匹配->向前探测->
    fn match_by_line_fast(
        &mut self,
        buf: &[u8],
    ) -> Result<FastMatchResult, S::Error> {
        use FastMatchResult::*;

        debug_assert!(!self.config.passthru);
        while !buf[self.pos()..].is_empty() {
            // 注：重复校验，如果不符合fast模式，切换到slow模式
            if self.config.stop_on_nonmatch && self.has_matched {
                return Ok(SwitchToSlow);
            }
            if self.config.invert_match {
                if !self.match_by_line_fast_invert(buf)? {
                    return Ok(Stop);
                }
            } else if let Some(line) = self.find_by_line_fast(buf)? {
                self.has_matched = true;
                if self.config.max_context() > 0 {
                    if !self.after_context_by_line(buf, line.start())? {
                        return Ok(Stop);
                    }
                    if !self.before_context_by_line(buf, line.start())? {
                        return Ok(Stop);
                    }
                }
                self.set_pos(line.end());
                if !self.sink_matched(buf, &line)? {
                    return Ok(Stop);
                }
            } else {
                break;
            }
        }
        if !self.after_context_by_line(buf, buf.len())? {
            return Ok(Stop);
        }
        self.set_pos(buf.len());
        Ok(Continue)
    }

    #[inline(always)]
    fn match_by_line_fast_invert(
        &mut self,
        buf: &[u8],
    ) -> Result<bool, S::Error> {
        assert!(self.config.invert_match);

        let invert_match = match self.find_by_line_fast(buf)? {
            None => {
                let range = Range::new(self.pos(), buf.len());
                self.set_pos(range.end());
                range
            }
            Some(line) => {
                let range = Range::new(self.pos(), line.start());
                self.set_pos(line.end());
                range
            }
        };
        if invert_match.is_empty() {
            return Ok(true);
        }
        self.has_matched = true;
        if !self.after_context_by_line(buf, invert_match.start())? {
            return Ok(false);
        }
        if !self.before_context_by_line(buf, invert_match.start())? {
            return Ok(false);
        }
        let mut stepper = LineStep::new(
            self.config.line_term.as_byte(),
            invert_match.start(),
            invert_match.end(),
        );
        while let Some(line) = stepper.next_match(buf) {
            if !self.sink_matched(buf, &line)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 注：该模式下，不需要先切分行，而是直接尝试匹配，匹配到了，根据位置再探测出line的位置
    #[inline(always)]
    fn find_by_line_fast(
        &self,
        buf: &[u8],
    ) -> Result<Option<Range>, S::Error> {
        debug_assert!(!self.searcher.multi_line_with_matcher(&self.matcher));
        debug_assert!(self.is_line_by_line_fast());

        let mut pos = self.pos();
        while !buf[pos..].is_empty() {
            // 注：相当于多行直接给matcher去匹配，返回第一个匹配项
            match self.matcher.find_candidate_line(&buf[pos..]) {
                Err(err) => return Err(S::Error::error_message(err)),
                Ok(None) => return Ok(None),
                Ok(Some(LineMatchKind::Confirmed(i))) => {
                    // 注：以i位置为基点，向前、向后探测出一个完整line
                    let line = lines::locate(
                        buf,
                        self.config.line_term.as_byte(),
                        Range::zero(i).offset(pos),
                    );
                    // If we matched beyond the end of the buffer, then we
                    // don't report this as a match.
                    if line.start() == buf.len() {
                        pos = buf.len();
                        continue;
                    }
                    return Ok(Some(line));
                }
                Ok(Some(LineMatchKind::Candidate(i))) => {
                    let line = lines::locate(
                        buf,
                        self.config.line_term.as_byte(),
                        Range::zero(i).offset(pos),
                    );
                    // We need to strip the line terminator here to match the
                    // semantics of line-by-line searching. Namely, regexes
                    // like `(?m)^$` can match at the final position beyond a
                    // line terminator, which is non-sensical in line oriented
                    // matching.
                    // 注：返回不包含换行符的line（即去除尾部的终止符）。
                    let slice = lines::without_terminator(
                        &buf[line],
                        self.config.line_term,
                    );
                    // 注：再来一次精确匹配
                    match self.matcher.is_match(slice) {
                        Err(err) => return Err(S::Error::error_message(err)),
                        Ok(true) => return Ok(Some(line)),
                        Ok(false) => {
                            pos = line.end();
                            continue;
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// 注：向sink发送匹配行数据（当前行）
    #[inline(always)]
    fn sink_matched(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        // 注：是否是二进制文件检测
        if self.binary && self.detect_binary(buf, range)? {
            return Ok(false);
        }
        // 注：不一致情况检测，如果有则发送中断给sink，sink返回false，则中断
        if !self.sink_break_context(range.start())? {
            return Ok(false);
        }
        // 注：计算line number
        self.count_lines(buf, range.start());
        // 注：计算line的绝对offset
        let offset = self.absolute_byte_offset + range.start() as u64;
        let linebuf = &buf[*range];
        // 注：向sink发送匹配行数据
        let keepgoing = self.sink.matched(
            &self.searcher,
            &SinkMatch {
                line_term: self.config.line_term,
                bytes: linebuf,
                absolute_byte_offset: offset,
                line_number: self.line_number,
                buffer: buf,
                bytes_range_in_buffer: range.start()..range.end(),
            },
        )?;
        if !keepgoing {
            return Ok(false);
        }
        // 注：更新已经发送的进度
        self.last_line_visited = range.end();
        self.after_context_left = self.config.after_context;
        self.has_sunk = true;
        Ok(true)
    }

    /// 注：向sink写一行数据，这里是写before部分行数据
    fn sink_before_context(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        if self.binary && self.detect_binary(buf, range)? {
            return Ok(false);
        }
        // 注：这里像重复执行，不过count_lines是幂等计算，
        self.count_lines(buf, range.start());
        // 注：计算line的绝对offset
        let offset = self.absolute_byte_offset + range.start() as u64;
        let keepgoing = self.sink.context(
            &self.searcher,
            &SinkContext {
                #[cfg(test)]
                line_term: self.config.line_term,
                bytes: &buf[*range],
                kind: SinkContextKind::Before,
                absolute_byte_offset: offset,
                line_number: self.line_number,
            },
        )?;
        if !keepgoing {
            return Ok(false);
        }
        // 注：更新before_context结果遍历进度
        self.last_line_visited = range.end();
        self.has_sunk = true;
        Ok(true)
    }

    /// 注：向sink输出after部分行数据
    fn sink_after_context(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        assert!(self.after_context_left >= 1);

        if self.binary && self.detect_binary(buf, range)? {
            return Ok(false);
        }
        self.count_lines(buf, range.start());
        let offset = self.absolute_byte_offset + range.start() as u64;
        let keepgoing = self.sink.context(
            &self.searcher,
            &SinkContext {
                #[cfg(test)]
                line_term: self.config.line_term,
                bytes: &buf[*range],
                kind: SinkContextKind::After,
                absolute_byte_offset: offset,
                line_number: self.line_number,
            },
        )?;
        if !keepgoing {
            return Ok(false);
        }
        self.last_line_visited = range.end();
        self.after_context_left -= 1;
        self.has_sunk = true;
        Ok(true)
    }

    fn sink_other_context(
        &mut self,
        buf: &[u8],
        range: &Range,
    ) -> Result<bool, S::Error> {
        if self.binary && self.detect_binary(buf, range)? {
            return Ok(false);
        }
        self.count_lines(buf, range.start());
        let offset = self.absolute_byte_offset + range.start() as u64;
        let keepgoing = self.sink.context(
            &self.searcher,
            &SinkContext {
                #[cfg(test)]
                line_term: self.config.line_term,
                bytes: &buf[*range],
                kind: SinkContextKind::Other,
                absolute_byte_offset: offset,
                line_number: self.line_number,
            },
        )?;
        if !keepgoing {
            return Ok(false);
        }
        self.last_line_visited = range.end();
        self.has_sunk = true;
        Ok(true)
    }

    /// 注：检测不一致情况时，发送中断通知给sink， sink可以决定是否要中断
    fn sink_break_context(
        &mut self,
        start_of_line: usize,
    ) -> Result<bool, S::Error> {
        let is_gap = self.last_line_visited < start_of_line;
        let any_context =
            self.config.before_context > 0 || self.config.after_context > 0;

        if !any_context || !self.has_sunk || !is_gap {
            Ok(true)
        } else {
            self.sink.context_break(&self.searcher)
        }
    }

    /// 注：统计buf中的行数，buf range为this.last_line_counted ~ upto
    fn count_lines(&mut self, buf: &[u8], upto: usize) {
        if let Some(ref mut line_number) = self.line_number {
            if self.last_line_counted >= upto {
                return;
            }
            let slice = &buf[self.last_line_counted..upto]; // 注：可读range的slice
            let count = lines::count(slice, self.config.line_term.as_byte()); // 注：统计slice内line_term数量，即行数
            *line_number += count; // 注：行号累加
            self.last_line_counted = upto; // 注：标记已统计的offset
        }
    }

    /// 注：判断是不是常规的按一个line_term字节进行行分割，如果是，返回true
    /// 常规定义：没有特殊的直通模式模式、不是关键词匹配直接退出模式 & 正则中没有line_term
    fn is_line_by_line_fast(&self) -> bool {
        debug_assert!(!self.searcher.multi_line_with_matcher(&self.matcher));

        // 注：配置了匹配直通模式，即返回所有内容
        if self.config.passthru {
            return false;
        }
        // 注：配置了配置关键词直接退出 & 且已经匹配到关键词
        if self.config.stop_on_nonmatch && self.has_matched {
            return false;
        }
        if let Some(line_term) = self.matcher.line_terminator() {
            // FIXME: This works around a bug in grep-regex where it does
            // not set the line terminator of the regex itself, and thus
            // line anchors like `(?m:^)` and `(?m:$)` will not match
            // anything except for `\n`. So for now, we just disable the fast
            // line-by-line searcher which requires the regex to be able to
            // deal with line terminators correctly. The slow line-by-line
            // searcher strips line terminators and thus absolves the regex
            // engine from needing to care about whether they are `\n` or NUL.
            if line_term.as_byte() == b'\x00' {
                return false;
            }
            if line_term == self.config.line_term {
                return true;
            }
        }
        if let Some(non_matching) = self.matcher.non_matching_bytes() {
            // If the line terminator is CRLF, we don't actually need to care
            // whether the regex can match `\r` or not. Namely, a `\r` is
            // neither necessary nor sufficient to terminate a line. A `\n` is
            // always required.
            // 注：判断正则表达式中是否包含line_term
            if non_matching.contains(self.config.line_term.as_byte()) {
                return true;
            }
        }
        false
    }
}
