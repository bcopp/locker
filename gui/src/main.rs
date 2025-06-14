use iced::{
    alignment, executor, Application, Command, Element, Length, Settings, Subscription,
    Theme, window, Color,
};

// Solarized color palette
const SOLARIZED_BASE03: Color = Color::from_rgb(0.0, 0.168627, 0.211765);    // Darkest
const SOLARIZED_BASE02: Color = Color::from_rgb(0.027451, 0.211765, 0.258824); // Dark
const SOLARIZED_BASE01: Color = Color::from_rgb(0.345098, 0.431373, 0.458824); // Light
const SOLARIZED_BASE0: Color = Color::from_rgb(0.513725, 0.580392, 0.588235);  // Lighter
const SOLARIZED_YELLOW: Color = Color::from_rgb(0.709804, 0.537255, 0.0);      // Accent

pub fn main() -> iced::Result {
    Locker::run(Settings {
        window: window::Settings {
            size: (800, 600),
            decorations: true,
            transparent: false,
            icon: Some(window::icon::from_file("../logo.png").unwrap()),
            ..Default::default()
        },
        ..Default::default()
    })
}

#[derive(Debug, Clone)]
pub enum Message {
    NewPressed,
    OpenPressed,
}

struct Locker {
    // State will be added here later
}

impl Application for Locker {
    type Message = Message;
    type Theme = Theme;
    type Executor = executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (Locker {}, Command::none())
    }

    fn title(&self) -> String {
        String::from("Locker")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::NewPressed => {
                // Handle new button press
                Command::none()
            }
            Message::OpenPressed => {
                // Handle open button press
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        use iced::widget::{Button, Column, Container, Row, Scrollable, Text};
        use iced::Alignment;

        let jobs_column = Container::new(
            Column::new()
                .width(Length::Fixed(200.0))
                .align_items(Alignment::Center)
                .push(
                    Text::new("Jobs")
                        .size(20)
                        .horizontal_alignment(alignment::Horizontal::Center)
                        .style(SOLARIZED_BASE0)
                )
                .push(
                    Scrollable::new(Column::new())
                        .width(Length::Fill)
                        .height(Length::Fill),
                )
        )
        .style(iced::theme::Container::Custom(Box::new(JobsColumnStyle)))
        .padding(10);

        let actions_column = Column::new()
            .width(Length::Fill)
            .height(Length::Fill)
            .align_items(Alignment::Center)
            .push(
                Container::new(
                    Column::new()
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .align_items(Alignment::Center)
                        .push(
                            Container::new(
                                Button::new(
                                    Text::new("New")
                                        .horizontal_alignment(alignment::Horizontal::Center)
                                        .vertical_alignment(alignment::Vertical::Center)
                                        .size(30)
                                        .style(SOLARIZED_BASE0)
                                )
                                .on_press(Message::NewPressed)
                                .padding(10)
                                .style(iced::theme::Button::Custom(Box::new(CustomButtonStyle)))
                                .height(Length::Fixed(100.0))
                                .width(Length::Fixed(300.0)),
                            )
                            .height(Length::Fill)
                            .align_y(alignment::Vertical::Center)
                        )
                )
                .height(Length::Fill)
                .width(Length::Fill),
            )
            .push(
                Row::new()
                    .push(
                        Container::new(Text::new(""))
                            .width(Length::Fill)
                            .height(Length::Fixed(1.0))
                            .style(iced::theme::Container::Custom(Box::new(SeparatorStyle)))
                    )
                    .push(
                        Text::new("Or")
                            .horizontal_alignment(alignment::Horizontal::Center)
                            .style(SOLARIZED_BASE0)
                    )
                    .push(
                        Container::new(Text::new(""))
                            .width(Length::Fill)
                            .height(Length::Fixed(1.0))
                            .style(iced::theme::Container::Custom(Box::new(SeparatorStyle)))
                    )
                    .align_items(Alignment::Center)
                    .spacing(10),
            )
            .push(
                Container::new(
                    Column::new()
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .align_items(Alignment::Center)
                        .push(
                            Container::new(
                                Button::new(
                                    Text::new("Open")
                                        .horizontal_alignment(alignment::Horizontal::Center)
                                        .vertical_alignment(alignment::Vertical::Center)
                                        .size(30)
                                        .style(SOLARIZED_BASE0)
                                )
                                .on_press(Message::OpenPressed)
                                .padding(10)
                                .style(iced::theme::Button::Custom(Box::new(CustomButtonStyle)))
                                .height(Length::Fixed(100.0))
                                .width(Length::Fixed(300.0)),
                            )
                            .height(Length::Fill)
                            .align_y(alignment::Vertical::Center)
                        )
                )
                .height(Length::Fill)
                .width(Length::Fill),
            );

        Container::new(
            Row::new()
                .push(jobs_column)
                .push(actions_column)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(iced::theme::Container::Custom(Box::new(CustomBackground)))
        .into()
    }
}

// Custom button style
struct CustomButtonStyle;

impl iced::widget::button::StyleSheet for CustomButtonStyle {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(SOLARIZED_BASE02)),
            text_color: SOLARIZED_BASE0,
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> iced::widget::button::Appearance {
        let active = self.active(style);
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(SOLARIZED_BASE01)),
            text_color: SOLARIZED_BASE0,
            ..active
        }
    }
}

// Custom container style
struct CustomBackground;

impl iced::widget::container::StyleSheet for CustomBackground {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(SOLARIZED_BASE03)),
            text_color: Some(SOLARIZED_BASE0),
            ..Default::default()
        }
    }
}

// Jobs column border style
struct JobsColumnStyle;

impl iced::widget::container::StyleSheet for JobsColumnStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(SOLARIZED_BASE03)),
            text_color: Some(SOLARIZED_BASE0),
            border_width: 1.0,
            border_radius: 0.0.into(),
            border_color: SOLARIZED_BASE02,
            ..Default::default()
        }
    }
}

// Custom separator style
struct SeparatorStyle;

impl iced::widget::container::StyleSheet for SeparatorStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(SOLARIZED_BASE02)),
            ..Default::default()
        }
    }
}




